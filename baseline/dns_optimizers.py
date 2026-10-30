import json

class DnsConfigGenerator:
    def optimize(self, input_filename, output_filename):
        with open(input_filename, 'rt') as f:
            data = json.load(f)
        print("All read data: {}".format(data))
        with open(output_filename, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

