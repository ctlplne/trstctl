package terraformprovider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const defaultPKITTLSeconds int64 = 3600

var (
	_ resource.Resource              = (*pkiCertificateResource)(nil)
	_ resource.ResourceWithConfigure = (*pkiCertificateResource)(nil)
)

type pkiCertificateResource struct {
	client *Client
}

type pkiCertificateResourceModel struct {
	ID             types.String `tfsdk:"id"`
	CommonName     types.String `tfsdk:"common_name"`
	TTLSeconds     types.Int64  `tfsdk:"ttl_seconds"`
	ReissueNonce   types.String `tfsdk:"reissue_nonce"`
	Serial         types.String `tfsdk:"serial"`
	CertificatePEM types.String `tfsdk:"certificate_pem"`
	PrivateKeyPEM  types.String `tfsdk:"private_key_pem"`
	IdempotencyKey types.String `tfsdk:"idempotency_key"`
}

func NewPKICertificateResource() resource.Resource {
	return &pkiCertificateResource{}
}

func (r *pkiCertificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pki_certificate"
}

func (r *pkiCertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		MarkdownDescription: "Short-lived certificate and private key issued through `POST /api/v1/secrets/pki`.",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Issued certificate serial.",
			},
			"common_name": rschema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Certificate common name.",
			},
			"ttl_seconds": rschema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Requested certificate TTL in seconds. Defaults to 3600.",
			},
			"reissue_nonce": rschema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Change this value to intentionally force a fresh idempotency identity for a reissue.",
			},
			"serial": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Issued certificate serial.",
			},
			"certificate_pem": rschema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Issued leaf certificate PEM.",
			},
			"private_key_pem": rschema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Issued private key PEM. Terraform stores sensitive values in state; protect the backend accordingly.",
			},
			"idempotency_key": rschema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Stable seed for mutation idempotency. When omitted, the provider derives one from common name, TTL, and nonce.",
			},
		},
	}
}

func (r *pkiCertificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if err := configureClient(req.ProviderData, &r.client); err != nil {
		resp.Diagnostics.AddError("Invalid provider data", err.Error())
	}
}

func (r *pkiCertificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pkiCertificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	issued, seed, ttl, err := r.issue(ctx, plan, "create")
	if err != nil {
		resp.Diagnostics.AddError("Issue trstctl PKI certificate", err.Error())
		return
	}
	plan.apply(issued, seed, ttl)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pkiCertificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pkiCertificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.Serial.IsNull() || state.Serial.IsUnknown() || state.Serial.ValueString() == "" {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *pkiCertificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pkiCertificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	issued, seed, ttl, err := r.issue(ctx, plan, "update")
	if err != nil {
		resp.Diagnostics.AddError("Reissue trstctl PKI certificate", err.Error())
		return
	}
	plan.apply(issued, seed, ttl)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pkiCertificateResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddWarning(
		"Issued certificates are immutable in trstctl",
		"Destroy removes the Terraform state binding only; revocation is handled by trstctl lifecycle or incident APIs, not by deleting this issued artifact.",
	)
	resp.State.RemoveResource(ctx)
}

func (r *pkiCertificateResource) issue(ctx context.Context, plan pkiCertificateResourceModel, operation string) (PKISecret, string, int64, error) {
	if r.client == nil {
		return PKISecret{}, "", 0, fmt.Errorf("provider is not configured")
	}
	commonName, err := requiredString(plan.CommonName, "common_name")
	if err != nil {
		return PKISecret{}, "", 0, err
	}
	ttl := defaultPKITTLSeconds
	if !plan.TTLSeconds.IsNull() && !plan.TTLSeconds.IsUnknown() {
		ttl = plan.TTLSeconds.ValueInt64()
	}
	if ttl <= 0 {
		return PKISecret{}, "", 0, fmt.Errorf("ttl_seconds must be positive")
	}
	nonce := optionalString(plan.ReissueNonce)
	seed := idempotencySeed(plan.IdempotencyKey, "pki_certificate", commonName)
	key := stableIdempotencyKey(seed, "pki_certificate", operation, commonName, strconv.FormatInt(ttl, 10), nonce)
	issued, err := r.client.IssuePKISecret(ctx, commonName, ttl, key)
	return issued, seed, ttl, err
}

func (m *pkiCertificateResourceModel) apply(p PKISecret, seed string, ttl int64) {
	m.ID = types.StringValue(p.Serial)
	m.CommonName = types.StringValue(p.CommonName)
	m.TTLSeconds = types.Int64Value(ttl)
	m.Serial = types.StringValue(p.Serial)
	m.CertificatePEM = types.StringValue(p.Certificate)
	m.PrivateKeyPEM = types.StringValue(p.PrivateKey)
	m.IdempotencyKey = types.StringValue(seed)
}
