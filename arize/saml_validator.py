import os

class SAMLValidator:
    def __init__(self, idp_data: dict):
        self.idp_data = idp_data

    def get_supported_domains(self):
        return {
            d.strip()
            for d in os.environ["SUPPORTED_DOMAINS"].split(",")
        }

    def get_expected_metadata_url(self):
        return (
            f"{os.environ['AUTHORIZER_BASE_URL']}/"
            f"{os.environ['TENANT_ID']}"
            f"{os.environ['AUTHORIZER_URL_PATH']}"
            f"?appid={os.environ['APP_ID']}"
        )

    def validate(self):
        supported_domains = self.get_supported_domains()
        expected_metadata_url = self.get_expected_metadata_url()

        edges = self.idp_data["account"]["samlIdPs"]["edges"]
        if not edges:
            raise RuntimeError("No SAML IdP configured")

        node = edges[0]["node"]

        actual_metadata_url = node["metadataUrl"]
        actual_domains = {d["domain"] for d in node["emailDomainsList"]}

        # ---- METADATA URL CHECK ----
        if actual_metadata_url != expected_metadata_url:
            raise RuntimeError(
                f"SAML metadata URL mismatch\n"
                f"Expected: {expected_metadata_url}\n"
                f"Actual:   {actual_metadata_url}"
            )

        # ---- DOMAIN CHECK ----
        unsupported = actual_domains - supported_domains
        if unsupported:
            raise RuntimeError(
                f"Unsupported email domains: {unsupported}\n"
                f"Allowed: {supported_domains}"
            )

        print("SAML validation successful")
