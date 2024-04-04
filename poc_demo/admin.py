from django.contrib import admin
from .models import  Product, Roles, Poc_model, Feature, Poc_remark, Status, Feature_status, CustomUser
# Register your models here.


admin.site.register(CustomUser)
admin.site.register(Product)
admin.site.register(Roles)
admin.site.register(Poc_model)
admin.site.register(Feature)
admin.site.register(Feature_status)
admin.site.register(Poc_remark)
admin.site.register(Status)