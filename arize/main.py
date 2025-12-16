from saml_validator import SAMLValidator
from idp_data import IDP_DATA


def main():
    validator = SAMLValidator(IDP_DATA)
    validator.validate()


if __name__ == "__main__":
    main()
