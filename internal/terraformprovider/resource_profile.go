package terraformprovider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*profileResource)(nil)
	_ resource.ResourceWithConfigure   = (*profileResource)(nil)
	_ resource.ResourceWithImportState = (*profileResource)(nil)
)

type profileResource struct {
	client *Client
}

type profileResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	SpecJSON       types.String `tfsdk:"spec_json"`
	Version        types.Int64  `tfsdk:"version"`
	Active         types.Bool   `tfsdk:"active"`
	CreatedBy      types.String `tfsdk:"created_by"`
	IdempotencyKey types.String `tfsdk:"idempotency_key"`
}

func NewProfileResource() resource.Resource {
	return &profileResource{}
}

func (r *profileResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_profile"
}

func (r *profileResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		MarkdownDescription: "Certificate profile version managed through `POST /api/v1/profiles`.",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "trstctl profile-version id.",
			},
			"name": rschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Profile name.",
			},
			"spec_json": rschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Profile specification JSON. trstctl validates the domain shape server-side.",
			},
			"version": rschema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Profile version created by trstctl.",
			},
			"active": rschema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether this version is the active profile version.",
			},
			"created_by": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Authenticated principal recorded by trstctl.",
			},
			"idempotency_key": rschema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Stable seed for mutation idempotency. When omitted, the provider derives one from the resource identity and desired JSON.",
			},
		},
	}
}

func (r *profileResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if err := configureClient(req.ProviderData, &r.client); err != nil {
		resp.Diagnostics.AddError("Invalid provider data", err.Error())
	}
}

func (r *profileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan profileResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	created, seed, err := r.apply(ctx, plan, "create")
	if err != nil {
		resp.Diagnostics.AddError("Create trstctl profile", err.Error())
		return
	}
	plan.apply(created, seed)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *profileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state profileResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := optionalString(state.Name)
	if name == "" || state.Version.IsNull() || state.Version.IsUnknown() {
		resp.State.RemoveResource(ctx)
		return
	}
	got, err := r.client.GetProfileVersion(ctx, name, state.Version.ValueInt64())
	if err != nil {
		if maybeNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read trstctl profile", err.Error())
		return
	}
	state.ID = types.StringValue(got.ID)
	state.Name = types.StringValue(got.Name)
	state.Version = types.Int64Value(got.Version)
	state.Active = types.BoolValue(got.Active)
	state.CreatedBy = types.StringValue(got.CreatedBy)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *profileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan profileResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	created, seed, err := r.apply(ctx, plan, "update")
	if err != nil {
		resp.Diagnostics.AddError("Update trstctl profile", err.Error())
		return
	}
	plan.apply(created, seed)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *profileResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Profile versions are immutable in trstctl",
		"Destroy removes the Terraform state binding only; trstctl keeps the event-sourced profile version for audit/replay.",
	)
	resp.State.RemoveResource(ctx)
}

func (r *profileResource) ImportState(_ context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.AddError("Import is not supported", "Import requires both profile name and version; use configuration to recreate the state binding.")
}

func (r *profileResource) apply(ctx context.Context, plan profileResourceModel, operation string) (Profile, string, error) {
	if r.client == nil {
		return Profile{}, "", fmt.Errorf("provider is not configured")
	}
	name, err := requiredString(plan.Name, "name")
	if err != nil {
		return Profile{}, "", err
	}
	spec, err := parseRawJSON(plan.SpecJSON.ValueString())
	if err != nil {
		return Profile{}, "", err
	}
	seed := idempotencySeed(plan.IdempotencyKey, "profile", name)
	key := stableIdempotencyKey(seed, "profile", operation, name, string(spec))
	created, err := r.client.CreateProfile(ctx, name, spec, key)
	return created, seed, err
}

func (m *profileResourceModel) apply(p Profile, seed string) {
	m.ID = types.StringValue(p.ID)
	m.Name = types.StringValue(p.Name)
	m.Version = types.Int64Value(p.Version)
	m.Active = types.BoolValue(p.Active)
	m.CreatedBy = types.StringValue(p.CreatedBy)
	m.IdempotencyKey = types.StringValue(seed)
}
