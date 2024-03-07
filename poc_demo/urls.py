from django.urls import path
from . import views

urlpatterns = [
    path('', views.dahboard, name='dashboard'),
    path('login/', views.login, name='loginpage'),
    path('add_poc/', views.add_poc, name='add_poc'),
    path('add_user/',views.add_user, name='add_users'),
    path('add_role/',views.add_role, name='add_role'),
    path('add_status/',views.add_status, name='add_status'),
    path('add_product/',views.add_product, name='add_product'),
    path('get_data_for/<str:usertype>/', views.get_data_for, name='get_data_for'),
    # path('flush_message/', views.flush_message, name='flush_message'),
]


