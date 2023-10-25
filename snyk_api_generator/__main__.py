from rest_openapi_parser import RestOpenApiParser
from rest_openapi_response_generator import RestOpenApiResponseGenerator


def main():
    parser = RestOpenApiParser("../static/snyk-api/rest-api/2023-09-20.json")
    generator = RestOpenApiResponseGenerator(parser.get_component_responses())
    generator.generate()


if __name__ == "__main__":
    main()
