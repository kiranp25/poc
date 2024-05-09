from django.core.exceptions import ValidationError
import os

def validate_file_extension(value):
    ext = os.path.splitext(value.name)[1]  # Get file extension
    print('ext', ext)
    valid_extensions = ['.pdf', '.zip']
    if not ext.lower() in valid_extensions:
        raise ValidationError(f"Unsupported file extension. Only {', '.join(valid_extensions)} files are allowed.")
