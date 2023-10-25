from string import Template
from string_helper import str
from http_status_code_map import HttpStatusCodeMap

import shutil


class RestOpenApiResponseGenerator:
    def __init__(self, data: dict) -> None:
        self.output_path = "../snyk_api/responses"
        self.data = data

    def generate(self) -> None:
        http_status_codes = HttpStatusCodeMap()

        # TODO: Need to support creating the directory structure if it does not yet exist
        shutil.copyfile("./templates/snyk_api/responses/base_response.py", "../snyk_api/responses/base_response.py")

        # TODO: WIP - Need to parse value for populating available headers
        for key, _ in self.data.items():
            key = int(key)
            template_mapping = {
                "ClassName": f"{str.camel_case(http_status_codes[key])}Response",
                "HttpStatusCode": key,
            }

            with open("./templates/response.template.txt", "r") as template_file:
                template = Template(template_file.read())
                result = template.substitute(template_mapping)
                
                output_file_path = (
                    f"{self.output_path}/{template_mapping['ClassName']}.py"
                )
                with open(output_file_path, "w") as output_file:
                    output_file.write(result)
