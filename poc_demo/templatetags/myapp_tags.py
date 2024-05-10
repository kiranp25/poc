from django import template

register = template.Library()

@register.filter(name='get_second_part')
def get_second_part(value):
    parts = value.split('/')
    return parts[1] if len(parts) > 1 else value