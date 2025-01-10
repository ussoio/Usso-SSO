def fill_template(template: dict | list | str, data: dict):
    if isinstance(template, dict):
        # For dictionaries, recursively apply fill_template to each value
        return {k: fill_template(v, data) for k, v in template.items()}
    elif isinstance(template, list):
        # For lists, recursively apply fill_template to each item
        return [fill_template(item, data) for item in template]
    elif isinstance(template, str):
        # For strings, format using the data dictionary
        try:
            return template.format(**data)
        except KeyError:
            # If a key in the template string is not found in the user dict, return the original string
            # Alternatively, you can handle this case differently based on your requirements
            return template
    else:
        # For any other type, return it as is
        return template
