package terraformprovider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = (*secretResource)(nil)
	_ resource.ResourceWithConfigure = (*secretResource)(nil)
)

type secretResource struct {
	client *Client
}

type secretResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Value          types.String `tfsdk:"value"`
	Version        types.Int64  `tfsdk:"version"`
	CreatedAt      types.String `tfsdk:"created_at"`
	UpdatedAt      types.String `tfsdk:"updated_at"`
	MutationNonce  types.String `tfsdk:"mutation_nonce"`
	IdempotencyKey types.String `tfsdk:"idempotency_key"`
}

func NewSecretResource() resource.Resource {
	return &secretResource{}
}

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		MarkdownDescription: "Application secret managed through `/api/v1/secrets/store`. Terraform stores sensitive values in state; protect the backend accordingly.",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Secret path/name.",
			},
			"name": rschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Hierarchical secret name, for example `apps/api/database_url`.",
			},
			"value": rschema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Secret value. trstctl seals it at rest; Terraform state still contains this sensitive value.",
			},
			"version": rschema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Current trstctl secret version.",
			},
			"created_at": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Creation timestamp returned by trstctl.",
			},
			"updated_at": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Update timestamp returned by trstctl.",
			},
			"mutation_nonce": rschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Optional non-secret value included in update/delete idempotency identities.",
			},
			"idempotency_key": rschema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Stable seed for mutation idempotency. When omitted, the provider derives one from the secret name.",
			},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if err := configureClient(req.ProviderData, &r.client); err != nil {
		resp.Diagnostics.AddError("Invalid provider data", err.Error())
	}
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name, value, seed, err := secretPlanFields(plan)
	if err != nil {
		resp.Diagnostics.AddError("Create trstctl secret", err.Error())
		return
	}
	key := stableIdempotencyKey(seed, "secret", "create", name, optionalString(plan.MutationNonce))
	meta, err := r.client.CreateSecret(ctx, name, value, key)
	if err != nil {
		resp.Diagnostics.AddError("Create trstctl secret", err.Error())
		return
	}
	plan.applyMeta(meta, seed)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := optionalString(state.Name)
	if name == "" {
		resp.State.RemoveResource(ctx)
		return
	}
	got, err := r.client.GetSecret(ctx, name)
	if err != nil {
		if maybeNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read trstctl secret", err.Error())
		return
	}
	state.ID = types.StringValue(got.Name)
	state.Name = types.StringValue(got.Name)
	state.Value = types.StringValue(got.Value)
	state.Version = types.Int64Value(got.Version)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan secretResourceModel
	var state secretResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name, value, seed, err := secretPlanFields(plan)
	if err != nil {
		resp.Diagnostics.AddError("Rotate trstctl secret", err.Error())
		return
	}
	oldVersion := int64(0)
	if !state.Version.IsNull() && !state.Version.IsUnknown() {
		oldVersion = state.Version.ValueInt64()
	}
	key := stableIdempotencyKey(seed, "secret", "update", name, strconv.FormatInt(oldVersion, 10), optionalString(plan.MutationNonce))
	meta, err := r.client.RotateSecret(ctx, name, value, key)
	if err != nil {
		resp.Diagnostics.AddError("Rotate trstctl secret", err.Error())
		return
	}
	plan.applyMeta(meta, seed)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := optionalString(state.Name)
	if name == "" {
		resp.State.RemoveResource(ctx)
		return
	}
	version := int64(0)
	if !state.Version.IsNull() && !state.Version.IsUnknown() {
		version = state.Version.ValueInt64()
	}
	seed := idempotencySeed(state.IdempotencyKey, "secret", name)
	key := stableIdempotencyKey(seed, "secret", "delete", name, strconv.FormatInt(version, 10), optionalString(state.MutationNonce))
	if err := r.client.DeleteSecret(ctx, name, key); err != nil && !maybeNotFound(err) {
		resp.Diagnostics.AddError("Delete trstctl secret", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

func secretPlanFields(plan secretResourceModel) (name, value, seed string, err error) {
	name, err = requiredString(plan.Name, "name")
	if err != nil {
		return "", "", "", err
	}
	if plan.Value.IsNull() || plan.Value.IsUnknown() {
		return "", "", "", fmt.Errorf("value is required")
	}
	value = plan.Value.ValueString()
	seed = idempotencySeed(plan.IdempotencyKey, "secret", name)
	return name, value, seed, nil
}

func (m *secretResourceModel) applyMeta(meta SecretMeta, seed string) {
	m.ID = types.StringValue(meta.Name)
	m.Name = types.StringValue(meta.Name)
	m.Version = types.Int64Value(meta.Version)
	m.CreatedAt = types.StringValue(meta.CreatedAt.Format(timeFormatRFC3339Nano))
	m.UpdatedAt = types.StringValue(meta.UpdatedAt.Format(timeFormatRFC3339Nano))
	m.IdempotencyKey = types.StringValue(seed)
}

const timeFormatRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
