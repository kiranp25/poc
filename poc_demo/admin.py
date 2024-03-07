from django.contrib import admin
from .models import Users, Product, Roles, Poc_model, Feature, Poc_remark, Status
# Register your models here.


admin.site.register(Users)
admin.site.register(Product)
admin.site.register(Roles)
admin.site.register(Poc_model)
admin.site.register(Feature)
admin.site.register(Poc_remark)
admin.site.register(Status)