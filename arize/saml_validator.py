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

        # ---- ALWAYS PRINT URLS ----
        print("========== SAML METADATA URL CHECK ==========")
        print("EXPECTED METADATA URL:")
        print(expected_metadata_url)
        print("--------------------------------------------")
        print("ACTUAL METADATA URL:")
        print(actual_metadata_url)
        print("============================================")

        # ---- METADATA URL CHECK ----
        if actual_metadata_url != expected_metadata_url:
            raise RuntimeError(
                "❌ SAML METADATA URL MISMATCH\n\n"
                "EXPECTED METADATA URL:\n"
                f"{expected_metadata_url}\n\n"
                "ACTUAL METADATA URL:\n"
                f"{actual_metadata_url}\n"
            )

        # ---- DOMAIN CHECK ----
        unsupported = actual_domains - supported_domains
        if unsupported:
            raise RuntimeError(
                "❌ UNSUPPORTED EMAIL DOMAINS\n\n"
                f"UNSUPPORTED: {unsupported}\n"
                f"ALLOWED: {supported_domains}"
            )

        print("✅ SAML validation successful")
