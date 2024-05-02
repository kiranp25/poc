from django.urls import path
from . import views

urlpatterns = [
    path('', views.dahboard, name='dashboard'),
    path('login/', views.login_page, name='loginpage'),
    path('add_poc/', views.add_poc, name='add_poc'),
    path('add_user/',views.add_user, name='add_users'),
    path('add_role/',views.add_role, name='add_role'),
    path('add_status/',views.add_status, name='add_status'),
    path('add_product/',views.add_product, name='add_product'),
    path('get_data_for/<str:usertype>/', views.get_data_for, name='get_data_for'),
    path('view_poc/',views.view_poc, name='view_poc'),
    path('update_sts/<int:id>',views.update_sts, name='update_sts'),
    path('view_poc_detail/<int:id>',views.view_poc_detail, name='view_poc_detail'),
    path('get_detail_sts/',views.get_detail_sts, name='get_detail_sts'),
    path('logout/', views.logout_page, name='logout_page'),
    path('view_users/', views.view_users, name='view_users'),
    path('edit_user/<int:id>', views.edit_user, name='edit_user'),
    path('edit_status/<int:id>', views.edit_status, name='edit_status'),
    path('view_status/', views.view_status, name='view_status'),
    path('view_product/', views.view_product, name='view_product'),   
    path('edit_product/<int:id>', views.edit_product, name='edit_product'),
    path('view_roles/', views.view_roles, name='view_roles'),
    path('edit_role/<int:id>', views.edit_role, name='edit_role'),
    path('delete_role/<int:id>', views.delete_role, name='delete_role'),     
    path('delete_user/<int:id>', views.delete_user, name='delete_user'), 
    path('delete_product/<int:id>', views.delete_product, name='delete_product'), 
    path('delete_status/<int:id>', views.delete_status, name='delete_status'), 
    # path('flush_message/', views.flush_message, name='flush_message'),
    path('edit_poc/<int:id>', views.edit_poc, name='edit_poc'),
    path('add_remarks/<int:id>', views.add_remarks, name='add_remarks'),
    path('update_feature_detail/', views.update_feature_detail, name='update_feature_detail'),
    path('delete_feature/', views.delete_feature, name='delete_feature'),
    path('add_feature/<int:id>', views.add_feature, name='add_feature'),
    path('add_demo/', views.add_demo, name='add_demo'),
    path('view_demo/', views.view_demo, name='view_demo'),
    path('edit_demo/<int:id>', views.edit_demo, name='edit_demo'),
    path('view_demo_detail/<int:id>',views.view_demo_detail, name='view_demo_detail'),
    path('add_demo_remarks/<int:id>',views.add_demo_remarks, name='add_demo_remarks'),
    path('get_detail_sts_demo/',views.get_detail_sts_demo, name='get_detail_sts_demo'),
    path('add_demo_feature/<int:id>', views.add_demo_feature, name='add_demo_feature'),
    path('demo_update_sts/<int:id>', views.demo_update_sts, name='demo_update_sts'),
    path('update_feature_detail_demo', views.update_feature_detail_demo, name='update_feature_detail_demo'),

    

    

    


    
    
]


