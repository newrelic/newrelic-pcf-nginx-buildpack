import yaml
from jinja2 import Template

# Function to increment semantic version
def increment_semantic_version(version_str):
    parts = version_str.split('.')
    major = int(parts[0])
    minor = int(parts[1])
    patch = int(parts[2])

    # Increment logic based on your rules
    patch += 1  # Increment patch version

    return f"{major}.{minor}.{patch}"

# Load tile-template.yml content
with open('tile-template.yml', 'r') as template_file:
    template_content = template_file.read()

# Load tile-history.yml content
with open('tile-history.yml', 'r') as history_file:
    history_data = yaml.safe_load(history_file)

# Extract and increment version
current_version = history_data.get('version', '0.0.1')
next_version = increment_semantic_version(current_version)

# Update history file with new version
#history_data['version'] = next_version
#with open('tile-history.yml', 'w') as history_file:
#    yaml.dump(history_data, history_file)

# Determine if cached keyword should be added
cached = history_data.get('cached', False)
cached_suffix = 'cached' if cached else ''

# Use Jinja2 to render the template
template = Template(template_content)
rendered_tile_yml = template.render(version=next_version, cached_suffix=cached_suffix)

# Write the rendered template to tile.yml
with open('tile.yml', 'w') as output_file:
    output_file.write(rendered_tile_yml)

# Update VERSION file with new version
with open('VERSION', 'w') as version_file:
    version_file.write(next_version + '\n')

# Generate pivotal filename
pivotal_filename = f"newrelic-pcf-nginx-buildpack-{next_version}.pivotal"

print(f"tile.yml successfully generated with version {next_version}.")
print(f"Pivotal filename generated: {pivotal_filename}")

