from django.shortcuts import render, redirect, HttpResponse, get_object_or_404
from .models import *
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from .form import CustomPasswordResetForm
from datetime import datetime
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
import threading

User = get_user_model()
app_name = 'POC_DEMO'


def mail_for_action(subject, message, recipient_list):
    try:
        message += f'<br><br><footer> Send By {app_name}<br>Olatechs solution</footer>'
        email_from = settings.EMAIL_HOST_USER
        msg = EmailMessage(subject, message, email_from, recipient_list)
        msg.content_subtype = "html"  # Main content is now text/html
        threading.Thread(target=msg.send).start()
    except Exception as e:
        pass


def user_has_permission(permission_name):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            back_page = request.META.get('HTTP_REFERER')
            # Check if the user has the required permission
            if request.user.permissions.filter(name=permission_name).exists():
                # If user has permission, call the view function
                return view_func(request, *args, **kwargs)
            else:
                # If user doesn't have permission, return forbidden response
                messages.error(request, f"You don't have permission to {permission_name}.", extra_tags='danger')
                if permission_name != 'manage_permissions':
                    return redirect(back_page)
                else:
                    return redirect('dashboard')

        return wrapper

    return decorator


@login_required(login_url='loginpage')
def dahboard(request):
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    user_types = request.user.role
    all_active_product = Product.objects.all()
    all_poc = Poc_model.objects.all()
    all_demo = Demo_model.objects.all()

    # if request.user.role.name == "Admin":
    #     all_poc = Poc_model.objects.all()
    #     all_demo = Demo_model.objects.all()
    # elif request.user.role.name == "Approval":
    #     all_poc = Poc_model.objects.filter(added_by__Belongs_to=request.user.id).all()
    #     all_demo = Demo_model.objects.filter(added_by__Belongs_to=request.user.id).all()
    # elif request.user.role.name == "Sales":
    #     all_poc = Poc_model.objects.filter(added_by=request.user.id).all()
    #     all_demo = Demo_model.objects.filter(added_by=request.user.id).all()
    # elif request.user.role.name == "Support":
    #     all_poc = Poc_model.objects.filter(assign_to=request.user.id).all()
    #     all_demo = Demo_model.objects.filter(added_by=request.user.id).all()
    all_customer = Customer.objects.all()
    all_users = User.objects.all()
    context = {'name': 'kp', 'user_type': user_types, 'Products': all_active_product, "poc": all_poc, "demo": all_demo,
               "user": all_users, "permission_names": permission_names, "all_customer": all_customer}
    return render(request, 'poc_demo/index.html', context)


def login_page(request):
    try:
        if request.method == 'POST':
            email = request.POST['email']
            password = request.POST['password']

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, 'User does not exist.', extra_tags="danger")
                return redirect('loginpage')

            if user:
                user = authenticate(username=user.username, password=password)
                if user is None:
                    messages.warning(request, 'Invalid password!')
                    return redirect('loginpage')
                else:
                    login(request, user)

                    content_type = ContentType.objects.get_for_model(Poc_model)
                    return redirect('dashboard')
    except Exception as e:
        pass
    return render(request, 'poc_demo/login.html', {})


def logout_page(request):
    logout(request)
    return redirect('loginpage')


@login_required(login_url='loginpage')
def get_data_for(request, usertype):
    flow = {"Admin": 'Admin', "Approval": 'Admin', "Sales": 'Approval', 'Support': 'Approval'}
    user_info = dict()
    # branch_list = cl_Branch.objects.filter(branch_name=request.POST.get('branch_list')).first()
    # needs to change with role_belongs_to from Roles models.
    if usertype in flow:
        user_type_id = Roles.objects.get(name=flow[usertype])
    else:
        user_type_id = Roles.objects.get(name=usertype)
    users = User.objects.filter(role=user_type_id).all()
    user_dict = dict()
    for data in users:
        if data.id not in user_dict:
            user_dict[data.id] = data.username

    user_info = {
        'list_of': user_dict,
    }
    return JsonResponse(user_info)


def change_password(request, user_id):
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    if not request.user.is_superuser:
        return redirect('/')  # Redirect non-admin users

    user = User.objects.get(pk=user_id)
    if request.method == 'POST':
        form = CustomPasswordResetForm(user, request.POST)
        if form.is_valid():
            form.save()
            mail_for_action('Changed Password', 'Password Reset Successfully By Admin', [user.email])
            return redirect('view_users')
    else:
        form = CustomPasswordResetForm(user)
    return render(request, 'poc_demo/change_password.html', {'form': form, "permission_names": permission_names})


@user_has_permission('add_poc')
@login_required(login_url='loginpage')
def add_poc(request):
    all_active_product = Product.objects.filter(status='1')
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    sts = Status.objects.all()
    customer = Customer.objects.filter(status='Active')
    type_poc = poc_choice
    context = {}
    context['type_poc'] = type_poc
    context['status'] = sts
    context['customer'] = customer
    context['permission_names'] = permission_names
    product_list = [product for product in all_active_product]
    if request.method == 'POST':
        try:
            product_name = Product.objects.get(Product_name=request.POST['product_name'])
            customer_name = Customer.objects.get(id=request.POST['CustomerName'])
            feature_count = request.POST['feature_count']
            features_list = request.POST.getlist('Feature_ids')
            features = request.POST.getlist('features')
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            type_poc = request.POST.get('poc_type')
            status = Status.objects.get(name=request.POST['status'])
            added_by = CustomUser.objects.get(id=request.user.id)
            Timeline = request.POST['timeline']
            remarks_list = ",".join(remarks)

            new_poc = Poc_model(Customer_name=customer_name, Product_name=product_name, status=status,
                                added_by=added_by, Timeline=Timeline, poc_type=type_poc)
            new_poc.save()
            style = ''' <style>
            table {
              border-collapse: collapse;
              width: 100%;
            }
            th, td {
              padding: 8px;
              border: 1px solid #ddd;
            }
            th {
              text-align: left;
              background-color: #f2f2f2;
            }
            </style>'''
            html_message = f"""\
            <html>
            <head>
            {style}
            </head>
            <body>
            <h2>You have a new {type_poc} project for Approval</h2>
            <p>Added By: {added_by.email}</p>
            <table>
              <tr>
                <th>Field</th>
                <th>Value</th>
              </tr>
              <tr>
                <td>Customer Name</td>
                <td>{customer_name}</td>
              </tr>
              <tr>
                <td>Product Name</td>
                <td>{product_name}</td>
              </tr>
                <td>Remarks</td>
                <td>{remarks_list}</td>  </tr>
              <tr>
                <td>Type of Project</td>
                <td>{type_poc}</td>
              </tr>
              <tr>
                <td>Status</td>
                <td>{status.name}</td>  </tr>
              <tr>
                <td>Timeline</td>
                <td>{Timeline}</td>
              </tr>
            </table>
            </body>
            </html>
            """
            mail_for_action(f'New Project Added: {type_poc}',
                            html_message,
                            [added_by.Belongs_to.email])

            poc_ref = Poc_model.objects.get(pk=new_poc.id)

            new_feature_list = []
            for feture in features:
                new_feature_list.append(
                    {'poc_id': poc_ref, 'features_list': feture, 'status': status, 'added_by': added_by})
            new_feature_list = []
            for j in features_list:
                new_feature_list.append({'poc_id': poc_ref, 'features_list': request.POST[f'features_{j}'],
                                         'timeline': request.POST[f'timeline_{j}'], 'status': status,
                                         'added_by': added_by})
                # Access created features and their status objects:
            features_lsts_added = []
            for data in new_feature_list:
                feature = Feature.objects.create(**data)  # Create the Feature object
                status_data = Feature_status.objects.create(feature=feature, status=status,
                                                            added_by=added_by)  # Create the Status object linked to the Feature
                features_lsts_added.append(status_data)
            messages.success(request, f" Project {type_poc} added successfully.")
            new_remarks_list = []
            for remark in remarks:
                new_remarks_list.append(
                    {'poc_id': poc_ref, 'remarks': remark, 'status': status, 'added_by': added_by})
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            return redirect('add_poc')
        except Exception as e:
            messages.error(request, f"Project {request.POST.get('poc_type')} not added.", extra_tags="danger")
    context['product_list'] = product_list
    return render(request, 'poc_demo/add_poc.html', context)


@user_has_permission('add_customer')
@login_required(login_url='loginpage')
def add_customer(request):
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    context = {}
    context['status'] = ['active', 'inactive']
    context['permission_names'] = permission_names

    if request.method == 'POST':
        result = dict()
        html_msg = ''
        try:
            existing_user = Customer.objects.filter(name=request.POST['customer_name']).first()
            existing_user_email = Customer.objects.filter(contact_email=request.POST['contact_email']).first()
            if existing_user or existing_user_email:
                messages.error(request, 'Customer already exist! Please choose different name or email.',
                               extra_tags="danger")
            else:
                if request.POST['customer_name']:
                    Customer.objects.create(name=request.POST['customer_name'],
                                            location=request.POST['location_address'],
                                            address=request.POST['address'],
                                            contact_person=request.POST['contact_person'],
                                            contact_number=request.POST['contact_number'],
                                            contact_email=request.POST['contact_email'])
                    messages.success(request, 'Customer added successfully.')
                    html_msg = f'''<h2> Customer Details: </h2>
                                <ul>
                                <li> <strong> Name: </strong> {request.POST['customer_name']} </li>
                                <li> <strong> Location: </strong> {request.POST['location_address']} </li>
                                <li> <strong> Address: </strong> {request.POST['address']} </li>
                                <li> <strong> Contact Person: </strong> {request.POST['contact_person']}</li>
                                                      <li> <strong> Contact Number: </strong> {request.POST['contact_number']} </li>
                                <li><strong> Contact Email: </strong>{request.POST['contact_email']} </li></ul>
                                <p> This customer was added by: [Added By: {request.user.email}]</p>
                                <p> Thank you for keeping our customer records up-to-date.</p>
                                <p> Best regards, <br></p>'''

                else:
                    messages.error(request, f'Customer name should not be blank.', extra_tags="danger")

            email_list = User.objects.values('email').filter(role__name='Sales')
            email_list = [item['email'] for item in email_list]
            if html_msg:
                mail_for_action(f'New customer added!', html_msg, email_list)
        except Exception as e:
            messages.error(request, f'Customer not added.', extra_tags="danger")
        return redirect('add_customer')
    return render(request, 'poc_demo/add_customer.html', context)


@user_has_permission('add_user')
@login_required(login_url='loginpage')
def add_user(request):
    flow = {"Admin": ['Admin', 'Approval', 'Sales'], "Approval": ['Sales'], "Sales": ''}
    user = User.objects.all()
    roles = Roles.objects.filter(status="1")
    sts = status_choice
    context = {}
    context['users'] = [i.first_name for i in user]
    user_type_dict = dict()
    context['roles'] = roles
    context['status'] = sts
    context['permission_names'] = list(request.user.permissions.values_list('name', flat=True))
    if request.method == 'POST':
        result = dict()
        try:
            existing_user = User.objects.filter(email=request.POST['email']).first()

            if existing_user:
                messages.error(request, 'Email address already in use! Please choose a different one.',
                               extra_tags="danger")
            else:
                sales_permission = ['add_poc', 'edit_poc', 'add_demo', 'edit_demo', 'add_customer', 'edit_customer',
                                    'add_product', 'edit_product', 'add_remark']
                approval_permission = ['edit_poc', 'edit_demo', 'approved_status', 'add_remark']
                support_permission = ['add_remark']

                usertype = Roles.objects.get(name=request.POST['usertype'])
                if usertype.name == 'Support':
                    permissions_to_skip = ['delete', 'edit']  # Permissions Support shouldn't have
                else:
                    permissions_to_skip = []
                first_name = request.POST['first_name']
                last_name = request.POST['last_name']
                email = request.POST['email']
                username = request.POST['username']
                password = request.POST['password']
                status = request.POST.get('status')
                new_user = User.objects.create(first_name=first_name, last_name=last_name, email=email,
                                               username=username,  role=usertype, Status=status)

                if request.POST['Belongs_to'] != "Self":
                    Belongs_to = User.objects.get(id=request.POST['Belongs_to'])
                    new_user.Belongs_to=Belongs_to
                else :
                    new_user.Belongs_to= new_user
                new_user.save()
                new_user.set_password(password)
                if usertype.name == 'Approval':
                    for permission_nm in approval_permission:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        new_user.permissions.add(permission)
                elif usertype.name == 'Sales':
                    for permission_nm in sales_permission:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        new_user.permissions.add(permission)
                elif usertype.name == 'Support':
                    for permission_nm in support_permission:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        new_user.permissions.add(permission)
                else:
                    roleuser = Roles.objects.get(id=usertype.id)
                    get_roles_permissions = roleuser.permissions.all()
                    for permission_nm in get_roles_permissions:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        new_user.permissions.add(permission)

                html_message = f'''Welcome {first_name} {last_name}, for journey with us. <br>
                                Name: {first_name} {last_name} <br>
                                Email: {email}<br>
                                Username: {username}<br>
                                User Type: {usertype.name}<br>
                               '''
                mail_for_action(f'Thank You for Join with us: {first_name} {last_name}',
                                html_message,
                                [new_user.Belongs_to.email, new_user.email])

                list_dict = {'poc': Poc_model, 'demo': Demo_model, 'fstatus': Feature_status,
                             'dstatus': Demo_Feature_status, 'user': User,
                             'premark': Poc_remark, 'dremark': Demo_remark,
                             'pfeature': Feature, 'dfeature': Demo_feature}
                new_user.save()
                messages.success(request, 'User added successfully.')
        except Exception as e:
            messages.error(request, f'User not added {e}', extra_tags="danger")
        return redirect('add_users')
    return render(request, 'poc_demo/add_user.html', context)


@login_required(login_url='loginpage')
def view_users(request):
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    user = User.objects.all()
    if request.method == 'POST':
        pass
    context = {
        "users": user,
        "status": status_choice,
        "permission_names": permission_names
    }

    return render(request, 'poc_demo/user_view.html', context)


@login_required(login_url='loginpage')
def view_customer(request):
    customer = Customer.objects.all()
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    if request.method == 'POST':
        pass
    context = {
        "customer": customer,
        "permission_names": permission_names
    }

    return render(request, 'poc_demo/view_customer.html', context)


@user_has_permission('edit_user')
@login_required(login_url='loginpage')
def edit_user(request, id):
    all_user = User.objects.all()
    user = get_object_or_404(User, pk=id)  # Fetch user by ID
    flow = {"Admin": ['Admin', 'Approval', 'Sales'], "Approval": ['Sales'], "Sales": ''}
    roles = Roles.objects.all()

    sts = status_choice
    context = {}
    user_type_dict = dict()

    if request.method == 'POST':
        try:
            existing_user = User.objects.filter(email=request.POST['email']).exclude(pk=user.id).first()

            if existing_user:
                messages.error(request, 'Email address already in use! Please choose a different one.',
                               extra_tags="danger")
            else:
                sales_permission = ['add_poc', 'edit_poc', 'add_demo', 'edit_demo', 'add_customer', 'edit_customer',
                                    'add_product', 'edit_product', 'add_remark']
                approval_permission = ['edit_poc', 'edit_demo', 'approved_status', 'edit_feature', 'delete_feature',
                                       'add_feature', 'add_remark']
                support_permission = ['add_remark']
                user.first_name = request.POST['first_name']
                user.last_name = request.POST['last_name']
                user.email = request.POST['email']
                user.username = request.POST['email']

                new_role = Roles.objects.get(name=request.POST['usertype'])
                user.role = new_role
                user.Status = request.POST.get('status')

                if request.POST['Belongs_to'] != "Self":
                    Belongs_to = User.objects.get(id=request.POST['Belongs_to'])
                    user.Belongs_to=Belongs_to
                else :
                    user.Belongs_to = user

                if new_role.name != 'Admin':
                    user.permissions.clear()
                if new_role.name == 'Approval':
                    for permission_nm in approval_permission:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        user.permissions.add(permission)
                elif new_role.name == 'Sales':
                    for permission_nm in sales_permission:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        user.permissions.add(permission)
                elif new_role.name == 'Support':
                    for permission_nm in support_permission:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        user.permissions.add(permission)
                else:
                    get_roles_permissions = new_role.permissions.all()
                    for permission_nm in get_roles_permissions:
                        permission, _ = CustomPermission.objects.get_or_create(name=permission_nm)
                        user.permissions.add(permission)
                user.save()
                messages.success(request, f'User: {user.email} updated successfully.')
                return redirect('edit_user', id=id)
        except Exception as e:
            messages.error(request, f'User: {user.email} not updated.', extra_tags="danger")
            return redirect('view_users')
    context = {'user': user, 'roles': roles, 'status': sts, 'all_user': all_user,
               'permission_names': list(request.user.permissions.values_list('name', flat=True))}

    return render(request, 'poc_demo/edit_user.html', context)


@user_has_permission('add_product')
@login_required(login_url='loginpage')
def add_product(request):
    context = dict()
    sts = status_choice
    context['status'] = sts
    context['permission_names'] = list(request.user.permissions.values_list('name', flat=True))
    if request.method == 'POST':
        result = dict()
        try:
            Product_name = (request.POST['product_name']).strip()
            existing_product = Product.objects.filter(Product_name=Product_name.lower()).first()
            if existing_product:
                messages.error(request, f"Product {Product_name} already exist!",
                               extra_tags="danger")
            else:
                status = request.POST.get('status')
                new_product = Product(Product_name=Product_name, status=status,
                                      added_by=CustomUser.objects.get(id=request.user.id))
                new_product.save()
                messages.success(request, f"Product: {Product_name} added successfully.")
                # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            messages.error(request, f"Product not added.", extra_tags="danger")
            error_message = 'not added'
        return redirect('add_product')
    return render(request, 'poc_demo/add_product.html', context)


def view_product(request):
    product = Product.objects.all()
    context = {"products": product, "status": status_choice,
               'permission_names': list(request.user.permissions.values_list('name', flat=True))}
    return render(request, 'poc_demo/view_products.html', context)


@user_has_permission('add_role')
@login_required(login_url='loginpage')
def add_role(request):
    context = dict()
    sts = status_choice
    context['status'] = sts
    context['permission_names'] = list(request.user.permissions.values_list('name', flat=True))
    context['permission_name'] = CustomPermission.objects.all().order_by('id')
    role_list = Roles.objects.all()
    context['role_list'] = role_list
    if request.method == 'POST':
        result = dict()
        try:
            Role_name = (request.POST['role_name']).strip()
            existing = Roles.objects.filter(name=Role_name.lower()).first()
            if existing:
                messages.error(request, f"Role: {Role_name} already Exist!",
                               extra_tags="danger")
            else:

                status = request.POST.get('status')
                new_role = Roles(name=Role_name, status=status)
                new_role.save()
                if request.POST.get('roleTop'):
                    if request.POST['roleTop'] != 'Self':
                        new_role.role_belongs_to = request.POST['roleTop']
                    else:
                        new_role.role_belongs_to = new_role
                new_role.save()
                msg = f"Role: {request.POST['role_name']} added successfully."
                permissions = request.POST.getlist('permissions')
                if permissions:
                    new_role.permissions.clear()
                    for permission_name in permissions:
                        if permission_name != "manage_permissions":
                            permission, _ = CustomPermission.objects.get_or_create(name=permission_name)
                            new_role.permissions.add(permission)
                    msg += f'Permission added for {new_role.name}'
                messages.success(request, msg)
        except Exception as e:
            messages.error(request, f"Role: {request.POST['role_name']} not added.", extra_tags="danger")
        return redirect('add_role')
    return render(request, 'poc_demo/add_roles.html', context)


@login_required(login_url='loginpage')
def view_roles(request):
    roles = Roles.objects.all()
    if request.method == 'POST':
        pass
    context = {"roles": roles, "status": status_choice,
               'permission_names': list(request.user.permissions.values_list('name', flat=True))}
    return render(request, 'poc_demo/view_roles.html', context)


@user_has_permission('edit_role')
@login_required(login_url='loginpage')
def edit_role(request, id):
    role_list = Roles.objects.all()
    try:
        # .exclude(pk=user.id)
        role = get_object_or_404(Roles, pk=id)
        roles_defined = ['Admin', 'Approval', 'Sales', 'Support']
        if request.method == "POST":
            Role_name = (request.POST['role_name']).strip()
            existing = Roles.objects.filter(name=Role_name.lower()).exclude(pk=id).first()
            if existing:
                messages.error(request, f"Role: {Role_name} not updated, Role name already taken!", extra_tags="danger")
            else:
                role.name = request.POST['role_name']
                role.status = request.POST.get('status')
                if request.POST.get('roleTop'):
                    role.role_belongs_to = Roles.objects.get(id=request.POST['roleTop'])
                role.save()
                msg = f"Role: {request.POST['role_name']} updated."
                permissions = request.POST.getlist('permissions')
                if permissions:
                    role.permissions.clear()
                    for permission_name in permissions:
                        if permission_name != "manage_permissions":
                            permission, _ = CustomPermission.objects.get_or_create(name=permission_name)
                            role.permissions.add(permission)
                    msg += f'Permission added for {role.name}'
                messages.success(request, msg)
                return redirect('edit_role', id=id)
    except Exception as e:
        messages.error(request, f"Role {request.POST['role_name']} not updated.{e}", extra_tags="danger")
        return redirect('edit_role', id=id)
    context = {'role': role, 'status': status_choice, 'roles_defined': roles_defined,
               'permission_names': list(request.user.permissions.values_list('name', flat=True)),
               'permission_name': CustomPermission.objects.all().order_by('id'), 'role_list': role_list}
    return render(request, 'poc_demo/edit_role.html', context)


@user_has_permission('edit_customer')
@login_required(login_url='loginpage')
def edit_customer(request, id):
    context = {}
    context['permission_names'] = list(request.user.permissions.values_list('name', flat=True))
    try:
        # .exclude(pk=user.id)
        customer = get_object_or_404(Customer, pk=id)
        status = ['Active', 'InActive']
        context = {'customer': customer,
                   'status': status,
                   }
        if request.method == "POST":
            customer_name = (request.POST['customer_name']).strip()
            existing = Roles.objects.filter(name=customer_name.lower()).exclude(pk=id).first()
            if existing:
                messages.error(request, f"Customer: {customer_name} not updated, customer name already taken!",
                               extra_tags="danger")
            else:
                customer.name = request.POST['customer_name']
                customer.status = request.POST.get('status')
                customer.location = request.POST['location_address']
                customer.address = request.POST['address']
                customer.contact_email = request.POST['contact_email']
                customer.contact_number = request.POST['contact_number']
                customer.contact_person = request.POST['contact_person']
                customer.save()
                messages.success(request, f"Customer "
                                          f": {request.POST['customer_name']} updated.")

    except Exception as e:
        messages.error(request, f"Customer {request.POST['customer_name']} not updated.", extra_tags="danger")

    return render(request, 'poc_demo/edit_customer.html', context)


@user_has_permission('add_status')
@login_required(login_url='loginpage')
def add_status(request):
    context = dict()
    context['permission_names'] = list(request.user.permissions.values_list('name', flat=True))
    if request.method == 'POST':
        result = dict()
        try:
            # Belongs_to = Users.objects.get(name=request.POST['Belongs_to'])
            sts = request.POST['status_name']
            if Status.objects.filter(name=(sts.strip()).lower()).count() > 0:
                messages.error(request, f'Status : {sts} already exist!', extra_tags="danger")
            else:
                Status.objects.create(name=sts)
                messages.success(request, f"Status: {sts} added successfully.")

            return redirect('add_status')

            # request.session['success_message'] = 'Successfully added!'
        except Exception as e:
            error_message = 'not added'
            messages.error(request, f"Status not added.", extra_tags="danger")
        return redirect('add_status')
    return render(request, 'poc_demo/add_status.html', context)


@login_required(login_url='loginpage')
def view_status(request):
    new_sts = Status.objects.all()

    if request.method == 'POST':
        pass
    context = {"status": new_sts, 'permission_names': list(request.user.permissions.values_list('name', flat=True))}
    return render(request, 'poc_demo/status_view.html', context)


@user_has_permission('edit_status')
@login_required(login_url='loginpage')
def edit_status(request, id):
    try:
        status = get_object_or_404(Status, pk=id)
        if request.method == "POST":
            if Status.objects.filter(name=request.POST['status_name'].lower()).exclude(pk=id).first():
                messages.error(request, f"Status: {request.POST['status_name']} already exist!", extra_tags="danger")
            else:
                status.name = request.POST['status_name']
                status.save()
                messages.success(request, f"Status: {request.POST['status_name']} updated.")
    except Exception as e:
        messages.error(request, f"Status: {request.POST['status_name']} not updated.", extra_tags="danger")
    context = {'status': status, 'permission_names': list(request.user.permissions.values_list('name', flat=True))}
    return render(request, 'poc_demo/edit_status.html', context)


@user_has_permission('edit_product')
@login_required(login_url='loginpage')
def edit_product(request, id):
    try:
        product = get_object_or_404(Product, pk=id)
        if request.method == "POST":
            if Product.objects.filter(Product_name=request.POST['product_name'].lower()).exclude(pk=id).first():
                messages.error(request, f"Product: {request.POST['product_name']} already exist!", extra_tags="danger")
            else:
                product.Product_name = request.POST['product_name']
                product.status = request.POST.get('status')  #request.POST.get('status')
                product.save()
                messages.success(request, f"Product: {request.POST['product_name']} updated.")
    except Exception as e:
        messages.error(request, f"Product: {request.POST['product_name']} not updated.", extra_tags="danger")
    context = {'product': product, 'status': status_choice,
               'permission_names': list(request.user.permissions.values_list('name', flat=True))}
    return render(request, 'poc_demo/edit_product.html', context)


@login_required(login_url='loginpage')
def view_poc(request):
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    all_active_product = Poc_model.objects.prefetch_related('poc_f_related', 'poc_r_related', ).all().order_by(
        '-updated_at')
    # if request.user.role.name == "Admin":
    #     all_active_product = Poc_model.objects.prefetch_related('poc_f_related', 'poc_r_related', ).all().order_by(
    #         '-updated_at')
    # elif request.user.role.name == "Approval":
    #     all_active_product = Poc_model.objects.filter(added_by__Belongs_to=request.user.id).prefetch_related(
    #         'poc_f_related', 'poc_r_related').all().order_by('-updated_at')
    # elif request.user.role.name == "Sales":
    #     all_active_product = Poc_model.objects.filter().prefetch_related('poc_f_related',
    #                                                                                              'poc_r_related').all().order_by(
    #         '-updated_at')
    # elif request.user.role.name == "Support":
    #     all_active_product = Poc_model.objects.filter(assign_to=request.user.id).prefetch_related('poc_f_related',
    #                                                                                               'poc_r_related').all().order_by(
    #         '-updated_at')
    search_query = request.GET.get('search', '')

    if search_query:
        if search_query:
            all_active_product = all_active_product.filter(
                Q(Customer_name__name__icontains=search_query) |
                Q(Requested_date__icontains=search_query) |
                Q(Timeline__icontains=search_query) |
                Q(added_by__username__icontains=search_query) |
                Q(Product_name__Product_name__icontains=search_query) |
                Q(status__name__icontains=search_query) |
                Q(assign_to__username__icontains=search_query)
            )
    paginator = Paginator(all_active_product, 10)
    page_number = request.GET.get('page')
    page = paginator.get_page(page_number)
    context = {'paginator': paginator, 'page': page}
    context["data"] = all_active_product
    context['search_query'] = search_query
    context['permission_names'] = permission_names

    return render(request, 'poc_demo/view_poc.html', context)


@user_has_permission('add_remark')
def add_remarks(request, id):
    try:
        if request.method == 'POST':
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_poc = Poc_model.objects.get(pk=rid)
            new_remarks_list = []
            html_message = '<div> New remark added!'
            for remark in remarks:
                html_message += '<ul>'
                html_message += '<li>'
                html_message += f'Remark: {remark}<br>'
                html_message += '</li>'
                new_remarks_list.append(
                    {'poc_id': get_poc, 'remarks': remark, 'status': get_poc.status, 'added_by': added_by})
            html_message += f'</ul><br> above remark added to  project id {get_poc.id} <br> Added By: {added_by.email}</div>'
            list_mail = []
            if request.user.role.name == "Approval":
                list_mail.append(request.user.email)

            else:
                list_mail.extend([request.user.email, request.user.Belongs_to.email])
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            mail_for_action(f'New Remark Added for {get_poc.poc_type} id {get_poc.id}', html_message, list_mail)

            messages.success(request, "Remark Added Successfully!")
            return redirect('view_poc_detail', id=id)
    except Exception as e:
        messages.error(request, "Remark Not Added!", extra_tags='danger')
        return redirect('view_poc_detail', id=id)


@user_has_permission('add_feature')
def add_feature(request, id):
    try:
        if request.method == 'POST':
            added_by = CustomUser.objects.get(id=request.user.id)
            features_list = request.POST.getlist('Feature_ids')
            poc_ref = Poc_model.objects.get(pk=id)
            features_lsts_added = []
            new_feature_list = []
            for j in features_list:
                features_lsts_added.append(request.POST[f'features_{j}'])
                new_feature_list.append({'poc_id': poc_ref, 'features_list': request.POST[f'features_{j}'],
                                         'timeline': request.POST[f'timeline_{j}'], 'status': 'Active',
                                         'added_by': added_by})
            for data in new_feature_list:
                feature = Feature.objects.create(**data)  # Create the Feature object
                status_data = Feature_status.objects.create(feature=feature, status="active",
                                                            added_by=added_by)  # Create the Status object linked to the Feature

            list_mail = []
            html_message = f'''New Feature Added. for project id {poc_ref.id}<br>
            <br>Features: {",".join(features_lsts_added)}.<br>
            Added By: {added_by.email}.<br>'''

            if request.user.role.name == "Approval":
                list_mail.append(request.user.email)

            else:
                list_mail.extend([request.user.email, request.user.Belongs_to.email])
            mail_for_action(f'New feature added for project id {poc_ref.id}', html_message,
                            list_mail)

            messages.success(request, f"New feature added successfully.")
            return redirect('view_poc_detail', id=id)
    except Exception as e:
        messages.error(request, f"feature not added.", extra_tags="danger")
        return redirect('view_poc_detail', id=id)


@user_has_permission('edit_poc')
@login_required(login_url='loginpage')
def edit_poc(request, id):
    get_poc = Poc_model.objects.get(pk=id)
    get_changes = []
    new_remarks_list = []
    allow = False
    edit_allow = False
    is_support = False
    is_edit = False
    try:
        if request.user.role.name == 'Sales' and get_poc.status.name == 'Rejected' and request.user == get_poc.added_by:
            edit_allow = True
            support_is = True
        elif request.user.role.name in ['Approval', 'Admin']:
            if request.user.id == get_poc.added_by.Belongs_to.id:
                edit_allow = True
                is_support = True
                is_edit = True
            else:
                edit_allow = False
                is_support = False
                is_edit = True
        elif request.user.role.name in ['Support']:
            edit_allow = True
            is_support = True
            is_edit = False
        else:
            messages.error(request, 'You have no permissions for edit')

        if request.user.role.name == 'Sales':
            if get_poc.status.name == 'Rejected' or get_poc.status.name == 'Pending':
                allow = True
            else:
                allow = False
                messages.error(request, 'You have no permissions for edit')
        elif request.user.role.name == 'Admin' or request.user.role.name == 'Approval':
            allow = True

        if request.method == 'POST' and allow and edit_allow:
            if request.POST.get('Timeline_date'):
                datetime_object = datetime.strptime(request.POST['Timeline_date'], "%Y-%m-%d")
                if get_poc.Timeline != datetime_object.date():
                    get_changes.append(f"Timeline changed {get_poc.Timeline} to {request.POST['Timeline_date']}")
                    new_remarks_list.append({'poc_id': get_poc,
                                             'remarks': f"Timeline changed {get_poc.Timeline} to {request.POST['Timeline_date']}",
                                             'status': get_poc.status, 'added_by': request.user})
            if request.POST.get('poc_type'):
                if get_poc.poc_type != request.POST.get('poc_type'):
                    get_changes.append('Project Type')
                    new_remarks_list.append({'poc_id': get_poc,
                                             'remarks': f"Project Type changed {get_poc.poc_type} to {request.POST.get('poc_type')}",
                                             'status': get_poc.status, 'added_by': request.user})
            if request.POST.get('kt_given'):
                sts = False
                sts_for = 'Not Provided'
                if get_poc.kt_given == False:
                    old_sts = 'Not Provided'
                else:
                    old_sts = 'Provided'
                if request.POST['kt_given'] == 'True':
                    sts = True
                    sts_for = "Provided"
                if get_poc.kt_given != sts:
                    get_changes.append(f"changes in KT is  {old_sts} to {sts_for}")
                    new_remarks_list.append({'poc_id': get_poc,
                                             'remarks': f"Status for KT given {old_sts} to {sts_for}",
                                             'status': get_poc.status, 'added_by': request.user})

            if request.POST.get('assign_edit'):
                if request.POST['assign_edit'] != 'None':
                    new_user = User.objects.get(pk=request.POST.get('assign_edit'))
                    if get_poc.assign_to != new_user:
                        if get_poc.assign_to:
                            get_changes.append(f"Project Assigned from {get_poc.assign_to} to {new_user}")
                            new_remarks_list.append({'poc_id': get_poc,
                                                     'remarks': f"Project Assigned from {get_poc.assign_to} to {new_user}",
                                                     'status': get_poc.status, 'added_by': request.user})
                        else:
                            get_changes.append(f"Project Assigned to {new_user}")
                            new_remarks_list.append({'poc_id': get_poc,
                                                     'remarks': f"Project Assigned to {new_user}",
                                                     'status': get_poc.status, 'added_by': request.user})

                        html_message = f"""
                        Hello {new_user.email},<br>
                        <br>
                        You have been assigned a new project.<br>

                        Project Details:<br>
                        - Project Type: {get_poc.poc_type}<br>
                        - Assigned By: {request.user.email}<br>
                        <br>
                        Please review the project details and take necessary actions accordingly.
                        <br><br>    
                        Best regards,<br>
                        """

                        mail_for_action(f'Project Assigned (Project {get_poc.poc_type})', html_message,
                                        [new_user.email])

            if request.POST.get('status'):
                new_sts = Status.objects.get(name=request.POST['status'])
                if get_poc.status != new_sts:
                    get_changes.append(f"Project Status changed  {get_poc.status} to {new_sts}")
                    new_remarks_list.append({'poc_id': get_poc,
                                             'remarks': f"Project Status changed  {get_poc.status} to {new_sts}",
                                             'status': get_poc.status, 'added_by': request.user})

            if request.user.role.name == 'Sales' and get_poc.description:
                status = Status.objects.get(name='Pending')

                get_poc.description = ''
                list_mail = [request.user.Belongs_to.email]
                mail_for_action(f'Project Request for Approve',
                                f' Project Request for Approve :- by {request.user.email}',
                                list_mail)
            else:
                if request.POST.get('status'):
                    status = Status.objects.get(name=request.POST['status'])
                else:
                    status = get_poc.status
            if request.POST.get('Timeline_date'):
                get_poc.Timeline = request.POST['Timeline_date']
            if request.POST.get('poc_type'):
                get_poc.poc_type = request.POST.get('poc_type')
            if request.POST.get('kt_given'):
                get_poc.kt_given = request.POST['kt_given']
            get_poc.status = status
            if request.POST.get('assign_edit'):
                if request.POST['assign_edit'] != 'None':
                    get_poc.assign_to = User.objects.get(pk=request.POST.get('assign_edit'))

            if request.FILES.get('uploaded_file'):
                uploaded_file = request.FILES['uploaded_file']
                if uploaded_file.name.endswith(('.zip', '.pdf')):
                    ext = (uploaded_file.name).split(".")[-1]
                    uploaded_file.name = f"{get_poc.Product_name.Product_name + '_' + get_poc.poc_type + '_documentations'}.{ext}"
                    get_poc.documentation = uploaded_file
                    new_remarks_list.append({'poc_id': get_poc,
                                             'remarks': f"New document uploaded for project. Name :{uploaded_file.name}",
                                             'status': get_poc.status, 'added_by': request.user})
                    get_changes.append(
                        f"New documentation uploaded for project.<br> Name : <b>{uploaded_file.name}</b>")

            message = '<ul>'
            for i in get_changes:
                message += f'<li>{i}</li><hr>'
            message += '</ul>'

            html_message = f"""
            Hello,<br>
            <br>
            Project Detail Updated! for {get_poc.poc_type}<br>
            <br>
            Project Details changes:<br>
            {message}<br>
            Changes By: <br>
            {request.user.email}<br>
            Please review the project details and take necessary actions accordingly.
            <br>
            Best regards,<br>
            """

            list_mail = []
            if request.user.role.name == "Approval":
                list_mail.append(request.user.email)

            else:
                list_mail.extend([request.user.email, request.user.Belongs_to.email])

            mail_for_action(f'Project Detail Updated! for {get_poc.poc_type}', html_message,
                            list_mail)
            get_poc.save()
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            messages.success(request, f"Project {get_poc.poc_type} updated.")
    except Exception as e:
        messages.error(request, f"Project {get_poc.poc_type} not updated. {e}", extra_tags="danger")
    return redirect('view_poc_detail', id=id)


@login_required(login_url='loginpage')
def update_sts(request, id):
    if request.method == 'POST':
        try:
            sts_id = request.POST['sts_id']
            status = request.POST['status']
            poc_id = request.POST['poc_id']
            obj = Poc_model.objects.get(id=poc_id)
            added_by = CustomUser.objects.get(id=request.user.id)
            featureobj = Feature.objects.get(pk=sts_id)
            Feature_status.objects.create(feature=featureobj, status=status, added_by=added_by)
            # return redirect('view_poc_detail', id=id)
            messages.success(request, 'Status added for feature')
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status  added.</h2> </div>')
        except Exception as e:
            # return redirect('view_poc_detail', id=id)
            messages.error(request, f'Status not added for feature', extra_tags='danger')
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status not added {e}.</h2> </div>')


@user_has_permission('edit_feature')
@login_required(login_url='loginpage')
def update_feature_detail(request):
    if request.method == 'POST':
        try:
            id = request.POST['id']
            feature = get_object_or_404(Feature, pk=id)
            get_poc = get_object_or_404(Poc_model, pk=feature.poc_id.id)
            html_message = f' Project Request for Approve :- by {request.user.email}'
            if request.user.role.name == 'Sales' and get_poc.description:
                get_poc.status = Status.objects.get(name='Pending')
                get_poc.description = ''
                list_mail = [request.user.Belongs_to.email]
                mail_for_action(f'Project Request for Approve',
                                html_message,
                                list_mail)
            get_poc.save()

            feature.features_list = request.POST['Feature_name']
            feature.status = request.POST['status']
            feature.timeline = request.POST['Feature_timeline']
            feature.added_by = CustomUser.objects.get(id=request.user.id)
            feature.save()
            list_mail = []
            if request.user.role.name == "Approval":
                list_mail.append(request.user.email)

            else:
                list_mail.extend([request.user.email, request.user.Belongs_to.email])

            html_ = f'''<div class="container">
    <h1>Feature Update</h1>
    <p>Here's the latest update on the features:</p>
    <ul class="feature-list">
      <li>Features: {feature.features_list}</li>
    </ul>
    <p>Status: <span class="status">{feature.status}</span></p>
  </div>'''
            mail_for_action(f'Feature Updated!', html_,
                            list_mail)

            messages.success(request, f"Feature: {request.POST['Feature_name']} updated.")
            return HttpResponse(
                '<div class="messages text-center alert alert-success"> <h2>  updated.</h2> </div>')
        except Exception as e:
            messages.error(request, f"Feature not updated.", extra_tags="danger")
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2>  not updated {e}.</h2> </div>')


@login_required(login_url='loginpage')
def view_poc_detail(request, id):
    edit_allow = False
    is_support = False
    is_edit = False
    is_allowed = False
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    poc = Poc_model.objects.prefetch_related('poc_f_related', 'poc_r_related').get(id=id)
    if request.user.role.name == 'Sales' and request.user == poc.added_by:
        if poc.status.name == 'Rejected':
            edit_allow = True
            is_support = True
            is_edit = True
        if poc.status.name not in ['Rejected', 'pending']:
            edit_allow = True
            is_support = True

    elif request.user.role.name in ['Approval', 'Admin']:
        if request.user.id == poc.added_by.Belongs_to.id:
            edit_allow = True
            is_edit = True
            is_support = True
            if poc.status.name == 'Pending':
                is_edit = False
        if request.user.role.name == 'Admin':
            is_support = True
            is_allowed = True
            is_edit = True

    elif request.user.role.name in ['Support']:
        if poc.assign_to == request.user:
            edit_allow = False
            is_edit = False
            is_support = True
    else:
        lists = request.user.permissions.all()
        ls = []
        for listss in lists:
            print(listss)
            ls.append(listss.name)
        if "add_remark" in ls:
            is_support = True
        edit_allow = False
        is_edit = False

    document = ''
    if poc.documentation.name:
        document = poc.documentation.name.split("/")[1]

    edited = False
    if request.user.permissions.filter(name="edit_poc").exists():
        edited = True
    add_remarked = False
    if request.user.permissions.filter(name="add_remark").exists():
        add_remarked = True
    add_feature = False
    if request.user.permissions.filter(name="add_feature").exists():
        add_feature = True

    edit_feature = False
    if request.user.permissions.filter(name="edit_feature").exists():
        edit_feature = True

    permission_for_edit = edited

    permission_for_delete = ['Admin', 'Sales']
    permission_for_ADD_STATUS = ['Admin', 'Sales', 'Approval', 'Support']
    html_feture_only = ''' '''
    html_feture_sts_only = ''' '''
    html = ''' '''
    type_poc = poc_choice

    for feature in poc.poc_f_related.all():
        elated_objects_count = feature.feature_related.count() + 1
        for data in feature.feature_related.all().order_by('-created_at'):
            html += f'''
                    <tr>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
            html_feture_sts_only += f'''
                    <tr>
                     <td>{feature.features_list}</td>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
    all_active_product = Product.objects.all()
    status_list = Status.objects.all()
    customer = Customer.objects.filter(status='Active')
    assign_to = User.objects.filter(role__name='Support', Belongs_to=request.user.id)
    permition = [1, 2, 3]
    if request.method == 'POST':
        try:
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            # status= request.POST['status'] 
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_poc = Poc_model.objects.get(pk=rid)
            new_remarks_list = []
            html_message = ''
            list_mail = []
            for remark in remarks:
                new_remarks_list.append(
                    {'poc_id': get_poc, 'remarks': remark, 'status': get_poc.status, 'added_by': added_by})

            html_message = '<ul>'
            for item in new_remarks_list:
                html_message += '<li>'
                html_message += f'Remarks: {item["remarks"]}<br>'
                html_message += f'Added by: {item["added_by"]}<br>'
                html_message += '</li>'
            html_message += '</ul>'

            if request.user.role.name == "Approval":
                list_mail.extend([get_poc.added_by.email,get_poc.assign_to.email])

            else:
                list_mail.extend([request.user.Belongs_to.email, get_poc.assign_to.email])
            Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            mail_for_action(f'Project Remarks Added! for {get_poc.poc_type}', html_message,
                            list_mail)

            return redirect('view_poc_detail', id=id)
        except Exception as e:
            pass
    return render(request, 'poc_demo/view_poc_detail.html', {'data': poc,
                                                             'status': status_list,
                                                             'html': html,
                                                             'product': all_active_product,
                                                             'permition': [1, 2, 3],
                                                             "assign_to": assign_to,
                                                             "html_feture_sts_only": html_feture_sts_only,
                                                             "html_feture_only": html_feture_only,
                                                             "permission_for_edit": permission_for_edit,
                                                             "permission_for_ADD_STATUS": permission_for_ADD_STATUS,
                                                             "permission_for_delete": permission_for_delete,
                                                             "add_remarked": add_remarked,
                                                             "add_feature": add_feature,
                                                             "edit_feature": edit_feature,
                                                             "type_poc": type_poc,
                                                             "customer": customer,
                                                             "permission_names": permission_names,
                                                             "document": document,
                                                             "edit_allow": edit_allow,
                                                             "is_support": is_support,
                                                             "is_edit": is_edit,
                                                             "is_allowed": is_allowed
                                                             })


@login_required(login_url='loginpage')
def get_detail_sts(request):
    sts_data = dict()
    if request.method == 'POST':
        id = request.POST.get('id')
        feature = Feature.objects.get(pk=id)
        get_data = Feature_status.objects.filter(feature=feature).order_by('-created_at')

        for data in get_data:
            sts_data[f'new_{data.id}'] = {'status': data.status, 'added_by': data.added_by.username,
                                          'time': data.created_at, 'feature': feature.features_list}
    return JsonResponse(sts_data)


@user_has_permission('delete_role')
@login_required(login_url='loginpage')
def delete_role(request, id):
    try:
        role = Roles.objects.get(pk=id)
        if role.name != 'Admin':
            role.status = '2'
            role.save()
            messages.success(request, 'Role deleted.')
        else:
            messages.error(request, f'Admin role can`t deleted.', extra_tags='danger')
        pass
    except Exception as e:
        messages.error(request, f'Role not deleted.', extra_tags='danger')
    return redirect('view_roles')


@user_has_permission('delete_customer')
@login_required(login_url='loginpage')
def delete_customer(request, id):
    try:
        customer = Customer.objects.get(pk=id)
        if request.user.role.name == 'Admin':
            # Customer.objects.get(pk=id).delete()
            customer.status = 'InActive'
            customer.save()
            messages.success(request, f'Customer {customer.name} deleted.')
        else:
            messages.error(request, f'Only Admin can delete permission.', extra_tags='danger')
        pass
    except Exception as e:
        messages.error(request, f'Customer not deleted.', extra_tags='danger')
    return redirect('view_customer')


@user_has_permission('delete_poc')
@login_required(login_url='loginpage')
def delete_poc(request, id):
    try:
        if request.user.role.name in ['Admin', 'Sales']:
            poc = Poc_model.objects.get(pk=id)
            poc.status = Status.objects.filter(name='InActive').first()
            poc.save()
            messages.success(request, 'Project deleted.')
        else:
            messages.error(request, ' Project not deleted. you haven`t permission', extra_tags='danger')
    except Exception as e:
        messages.error(request, f'Project not deleted.', extra_tags='danger')
    return redirect('view_poc')


@user_has_permission('delete_demo')
@login_required(login_url='loginpage')
def delete_demo(request, id):
    try:
        if request.user.role.name in ['Admin', 'Sales']:
            demo = Demo_model.objects.get(pk=id)
            demo.status = Status.objects.filter(name='InActive').first()
            demo.save()
            messages.success(request, 'DEMO deleted.')
        else:
            messages.error(request, ' DEMO not deleted. you haven`t permission', extra_tags='danger')
    except Exception as e:
        messages.error(request, f'DEMO not deleted.', extra_tags='danger')
    return redirect('view_demo')


@user_has_permission('delete_product')
@login_required(login_url='loginpage')
def delete_product(request, id):
    try:
        check = True
        product = Product.objects.get(pk=id)
        if check:
            Product.status = '2'
            product.save()
            messages.success(request, f'Product {product.Product_name} deleted.')
    except Exception as e:
        messages.error(request, f'Product not deleted.', extra_tags='danger')
    return redirect('view_product')


@user_has_permission('delete_user')
@login_required(login_url='loginpage')
def delete_user(request, id):
    try:
        if id != 1:
            user = User.objects.get(pk=id)
            user.Status = "2"
            user.save()
            messages.success(request, f'User {user.email} deleted.')
        else:
            messages.error(request, 'Admin user can`t deleted', extra_tags='danger')
    except Exception as e:
        messages.error(request, f'User not deleted', extra_tags='danger')
    return redirect('view_users')


@user_has_permission('delete_status')
@login_required(login_url='loginpage')
def delete_status(request, id):
    try:
        sts = Status.objects.get(pk=id)
        if sts.name.lower() in ['active', 'inactive', 'pending', 'rejected', 'approved']:
            messages.error(request, f'Status can`t deleted. no permission for delete {sts.name} status!', extra_tags = 'warning')
        else:
            sts.delete()
            messages.success(request, 'Status deleted.')
    except Exception as e:
        messages.error(request, f'Status not deleted.', extra_tags='danger')
    return redirect('view_status')


@user_has_permission('add_demo')
@login_required(login_url='loginpage')
def add_demo(request):
    all_active_product = Product.objects.filter(status='1')
    customer = Customer.objects.filter(status='Active')
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    sts = Status.objects.all()
    context = {}
    context['customer'] = customer
    context['status'] = sts
    context['permission_names'] = permission_names
    product_list = [product for product in all_active_product]

    if request.method == 'POST':
        try:
            customer_name = Customer.objects.get(id=request.POST['CustomerName'])
            # product_name = request.POST['product_name']
            product_name = Product.objects.get(Product_name=request.POST['product_name'])
            feature_count = request.POST['feature_count']
            features_list = request.POST.getlist('Feature_ids')
            features = request.POST.getlist('features')
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            # status= request.POST['status'] 
            status = Status.objects.get(name=request.POST['status'])
            added_by = CustomUser.objects.get(id=request.user.id)
            Timeline = request.POST['timeline']
            # features_list = ",".join(features)
            remarks_list = ",".join(remarks)

            new_demo = Demo_model(Customer_name=customer_name, Product_name=product_name, status=status,
                                  added_by=added_by, Timeline=Timeline)
            new_demo.save()

            demo_ref = Demo_model.objects.get(pk=new_demo.id)
            new_feature_list = []
            for j in features_list:
                new_feature_list.append({'demo_id': demo_ref, 'features_list': request.POST[f'features_{j}'],
                                         'timeline': request.POST[f'timeline_{j}'], 'status': status,
                                         'added_by': added_by})
            # Access created features and their status objects:
            features_lsts_added = []
            for data in new_feature_list:
                feature = Demo_feature.objects.create(**data)  # Create the Feature object
                status_data = Demo_Feature_status.objects.create(feature=feature, status=status,
                                                                 added_by=added_by)  # Create the Status object linked to the Feature
                features_lsts_added.append(status_data)
            messages.success(request, "Demo added successfully.")
            new_remarks_list = []
            style = ''' <style>
                            table {
                              border-collapse: collapse;
                              width: 100%;
                            }
                            th, td {
                              padding: 8px;
                              border: 1px solid #ddd;
                            }
                            th {
                              text-align: left;
                              background-color: #f2f2f2;
                            }
                            </style>'''
            html_message = f"""\
                            <html>
                            <head>
                            {style}
                            </head>
                            <body>
                            <h2>You have a new Demo project for Approval</h2>
                            <p>Added By: {added_by.email}</p>
                            <table>
                              <tr>
                                <th>Field</th>
                                <th>Value</th>
                              </tr>
                              <tr>
                                <td>Customer Name</td>
                                <td>{customer_name}</td>
                              </tr>
                              <tr>
                                <td>Product Name</td>
                                <td>{product_name}</td>
                              </tr>
                                <td>Remarks</td>
                                <td>{remarks_list}</td>  </tr>
                              <tr>
                                <td>Type of Project</td>
                                <td>Demo</td>
                              </tr>
                              <tr>
                                <td>Status</td>
                                <td>{status.name}</td>  </tr>
                              <tr>
                                <td>Timeline</td>
                                <td>{Timeline}</td>
                              </tr>
                            </table>
                            </body>
                            </html>
                            """
            for remark in remarks:
                new_remarks_list.append(
                    {'demo_id': demo_ref, 'remarks': remark, 'status': status, 'added_by': added_by})
            Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])
            mail_for_action(f'New Demo Added: ', html_message,
                            [added_by.email, added_by.Belongs_to.email])
            return redirect('add_demo')
        except Exception as e:
            messages.error(request, f"Demo not added.", extra_tags="danger")

    context['product_list'] = product_list
    return render(request, 'poc_demo/add_demo.html', context)


@login_required(login_url='loginpage')
def view_demo(request):
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    all_active_product = Demo_model.objects.prefetch_related('demo_f_related', 'demo_r_related').all()
    search_query = request.GET.get('search', '')

    if search_query:
        if search_query:
            all_active_product = all_active_product.filter(
                Q(Customer_name__name__icontains=search_query) |
                Q(Requested_date__icontains=search_query) |
                Q(Timeline__icontains=search_query) |
                Q(added_by__username__icontains=search_query) |
                Q(Product_name__Product_name__icontains=search_query) |
                Q(status__name__icontains=search_query)
            )

    paginator = Paginator(all_active_product, 10)
    page_number = request.GET.get('page')
    page = paginator.get_page(page_number)
    context = {'paginator': paginator, 'page': page}
    context["data"] = all_active_product
    context['search_query'] = search_query
    context['permission_names'] = permission_names
    return render(request, 'poc_demo/view_demo.html', context)


@login_required(login_url='loginpage')
def view_demo_detail(request, id):
    edit_allow = False
    is_support = False
    is_edit = False
    is_allowed = False
    permission_names = list(request.user.permissions.values_list('name', flat=True))
    permission_for_edit = ['Admin', 'Sales', 'Approval']
    permission_for_delete = ['Admin', 'Sales', 'Approval']
    permission_for_ADD_STATUS = ['Admin', 'Sales', 'Approval', 'Support']
    demo = Demo_model.objects.prefetch_related('demo_f_related', 'demo_r_related').get(id=id)
    html_feture_only = ''' '''
    html_feture_sts_only = ''' '''
    html = ''' '''

    if request.user.role.name == 'Sales' and request.user == demo.added_by:
        if demo.status.name == 'Rejected':
            edit_allow = True
            is_support = True
            is_edit = True
        if demo.status.name not in ['Rejected', 'pending']:
            edit_allow = True
            is_support = True

    elif request.user.role.name in ['Approval', 'Admin']:
        if request.user.id == demo.added_by.Belongs_to.id:
            edit_allow = True
            is_edit = True
            is_support = True

            if demo.status.name == 'Pending':
                is_edit = False

        if request.user.role.name == 'Admin':
            is_support = True
            is_allowed = True

    elif request.user.role.name in ['Support']:
        if demo.assign_to == request.user:
            edit_allow = False
            is_edit = False
            is_support = True
    else:
        lists = request.user.permissions.all()
        ls = []
        for listss in lists:
            print(listss)
            ls.append(listss.name)
        if "add_remark" in ls:
            is_support = True
        edit_allow = False
        is_edit = False

    document = ''
    if demo.documentation.name:
        document = demo.documentation.name.split("/")[1]

    for feature in demo.demo_f_related.all():
        elated_objects_count = feature.demo_feature_related.count() + 1
        for data in feature.demo_feature_related.all().order_by('-created_at'):
            html += f'''
                    <tr>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
            html_feture_sts_only += f'''
                    <tr>
                     <td>{feature.features_list}</td>
                    <td>{data.status}</td>
                      <td>{data.added_by}</td>
                      <td>{data.created_at}</td>
                      </tr>'''
    all_active_product = Product.objects.all()
    status_list = Status.objects.all()
    customer = Customer.objects.filter(status='Active')
    assign_to = User.objects.filter(role=4)
    permition = [1, 2, 3]
    if request.method == 'POST':
        try:
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            # status= request.POST['status'] 
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_demo = Demo_model.objects.get(pk=rid)
            new_remarks_list = []
            list_mail = []
            for remark in remarks:
                new_remarks_list.append(
                    {'demo_id': get_demo, 'remarks': remark, 'status': get_demo.status, 'added_by': added_by})
            Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])
            html_message = '<ul>'
            for item in new_remarks_list:
                html_message += '<li>'
                html_message += f'Remarks: {item["remarks"]}<br>'
                html_message += f'Added by: {item["added_by"]}<br>'
                html_message += '</li>'
            html_message += '</ul>'
            if request.user.role.name == "Approval":
                list_mail.extend([get_demo.added_by.email, get_demo.assign_to.email])

            else:
                list_mail.extend([request.user.Belongs_to.email, get_demo.assign_to.email])
            mail_for_action(f'Project Remarks Added! for Demo', html_message,
                            list_mail)

            return redirect('view_demo_detail', id=id)
        except Exception as e:
            pass
    return render(request, 'poc_demo/view_demo_detail.html', {'data': demo,
                                                              'status': status_list,
                                                              'html': html,
                                                              'product': all_active_product,
                                                              'permition': [1, 2, 3],
                                                              "assign_to": assign_to,
                                                              "html_feture_sts_only": html_feture_sts_only,
                                                              "html_feture_only": html_feture_only,
                                                              "permission_for_edit": permission_for_edit,
                                                              "permission_for_ADD_STATUS": permission_for_ADD_STATUS,
                                                              "permission_for_delete": permission_for_delete,
                                                              'customer': customer,
                                                              "permission_names": permission_names,
                                                              "document": document,
                                                              "is_allowed":is_allowed,
                                                              "is_edit":is_edit,
                                                              "is_support":is_support
                                                              })


@user_has_permission('edit_demo')
@login_required(login_url='loginpage')
def edit_demo(request, id):
    get_demo = Demo_model.objects.get(pk=id)
    new_remarks_list = []
    get_changes = []
    allow = False
    edit_allow = False
    is_support = False
    is_edit = False

    try:
        if request.user.role.name == 'Sales' and get_demo.status.name == 'Rejected' and request.user == get_demo.added_by:
            edit_allow = True
            support_is = True
        elif request.user.role.name in ['Approval', 'Admin']:
            if request.user.id == get_demo.added_by.Belongs_to.id:
                edit_allow = True
                is_support = True
                is_edit = True
            else:
                edit_allow = False
                is_support = False
                is_edit = True
        elif request.user.role.name in ['Support']:
            edit_allow = True
            is_support = True
            is_edit = False
        else:
            messages.error(request, 'You have no permissions for edit')

        if request.user.role.name == 'Sales':
            if get_demo.status.name == 'Rejected' or get_demo.status.name == 'Pending':
                allow = True
            else:
                allow = False
                messages.error(request, 'You have no permissions for edit')
        elif request.user.role.name == 'Admin' or request.user.role.name == 'Approval':
            allow = True

        if request.method == 'POST' and allow and edit_allow:
            datetime_object = datetime.strptime(request.POST['Timeline_date'], "%Y-%m-%d")
            if get_demo.Timeline != datetime_object.date():
                get_changes.append(f"Timeline changed {get_demo.Timeline} to {request.POST['Timeline_date']}")
                new_remarks_list.append({'demo_id': get_demo,
                                         'remarks': f"Timeline changed {get_demo.Timeline} to {request.POST['Timeline_date']}",
                                         'status': get_demo.status, 'added_by': request.user})
            if request.POST.get('demo_type'):
                if get_demo.demo_type != request.POST.get('demo_type'):
                    get_changes.append(f"Project Type changed {get_demo.demo_type} to {request.POST.get('demo_type')}")
                    new_remarks_list.append({'demo_id': get_demo,
                                             'remarks': f"Project Type changed {get_demo.demo_type} to {request.POST.get('demo_type')}",
                                             'status': get_demo.status, 'added_by': request.user})
            if request.POST.get('kt_given'):
                sts = False
                sts_for = 'Not Provided'
                if not get_demo.kt_given:
                    old_sts = 'Not Provided'
                else:
                    old_sts = 'Provided'
                if request.POST['kt_given'] == 'True':
                    sts = True
                    sts_for = "Provided"
                if get_demo.kt_given != sts:
                    get_changes.append(f"changes in KT is  {old_sts} to {sts_for}")
                    new_remarks_list.append({'demo_id': get_demo,
                                             'remarks': f"changes in KT is  {old_sts} to {sts_for}",
                                             'status': get_demo.status, 'added_by': request.user})

            if request.POST.get('assign_edit'):
                if request.POST['assign_edit'] != 'None':
                    new_user = User.objects.get(pk=request.POST.get('assign_edit'))
                    if get_demo.assign_to != new_user:
                        if get_demo.assign_to:
                            get_changes.append(f"Project Assign changed  {get_demo.assign_to} to {new_user}")
                            new_remarks_list.append({'demo_id': get_demo,
                                                     'remarks': f"Project Assign changed  {get_demo.assign_to} to {new_user}",
                                                     'status': get_demo.status, 'added_by': request.user})
                        else:
                            get_changes.append(f"Project Assigned to {new_user}")
                            new_remarks_list.append({'demo_id': get_demo,
                                                     'remarks': f"Project Assigned to {new_user}",
                                                     'status': get_demo.status, 'added_by': request.user})

                        html_message = f"""
                                               Hello {new_user.email},<br>
                                               <br>
                                               You have been assigned a new project.<br>

                                               Project Details:<br>
                                               - Project Type: {get_demo.demo_type}<br>
                                               - Assigned By: {request.user.email}<br>
                                               <br>
                                               Please review the project details and take necessary actions accordingly.
                                               <br><br>    
                                               Best regards,<br>
                                               """

                        mail_for_action('Project Assigned (Demo)',
                                        html_message,
                                        [new_user.email, request.user.email])
            if request.POST.get('status'):
                new_sts = Status.objects.get(name=request.POST['status'])
                if get_demo.status != new_sts:
                    get_changes.append(f"Project Status Changed  {get_demo.status} to {new_sts}")
                    new_remarks_list.append({'demo_id': get_demo,
                                             'remarks': f"Project Status Changed  {get_demo.status} to {new_sts}",
                                             'status': get_demo.status, 'added_by': request.user})

            if request.user.role.name == 'Sales' and get_demo.description:
                status = Status.objects.get(name='Pending')
                get_demo.description = ''
                list_mail = [request.user.Belongs_to.email]
                mail_for_action(f'Project Request for Approve',
                                f'Project Request for Approve :- by {request.user.email}',
                                list_mail)
            else:
                if request.POST['status']:
                    status = Status.objects.get(name=request.POST['status'])
                else:
                    status = get_demo.status
            # if request.POST.get('product_name'):
            #     product_name = Product.objects.get(Product_name=request.POST['product_name'])
            #     get_poc.Product_name = product_name

            # get_poc.Customer_name = Customer.objects.get(id=request.POST['Customer_name'])
            get_demo.Timeline = request.POST['Timeline_date']
            # if request.POST.get('poc_type'):
            #     get_demo.poc_type = request.POST.get('poc_type')
            if request.POST.get('kt_given'):
                get_demo.kt_given = request.POST['kt_given']
            get_demo.status = status
            if request.POST.get('assign_edit'):
                if request.POST['assign_edit'] != 'None':
                    get_demo.assign_to = User.objects.get(pk=request.POST.get('assign_edit'))

            if request.FILES.get('uploaded_file'):
                uploaded_file = request.FILES['uploaded_file']
                if uploaded_file.name.endswith(('.zip', '.pdf')):
                    ext = (uploaded_file.name).split(".")[-1]
                    uploaded_file.name = f"{get_demo.Product_name.Product_name + '_' + get_demo.demo_type + '_documentations'}.{ext}"
                    get_demo.documentation = uploaded_file
                    new_remarks_list.append({'demo_id': get_demo,
                                             'remarks': f"New Documentation Uploaded To Project. Name :{uploaded_file.name}",
                                             'status': get_demo.status, 'added_by': request.user})
                    get_changes.append(f"Project Documents Uploaded: {uploaded_file.name}")
            get_demo.save()
            list_mail = []
            html_message = ''
            for i in get_changes:
                html_message += i
                html_message += '<hr>'
            if request.user.role.name == "Approval":
                list_mail.append(request.user.email)

            else:
                list_mail.extend([request.user.email, request.user.Belongs_to.email])
            mail_for_action(f'Project Remarks Added! For Demo', html_message,
                            list_mail)
            Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])
            messages.success(request, 'Demo successfully updated.')
    except Exception as e:
        messages.error(request, f"Demo not updated.", extra_tags="danger")
    return redirect('view_demo_detail', id=id)


@user_has_permission('add_remark')
@login_required(login_url='loginpage')
def add_demo_remarks(request, id):
    try:
        if request.method == 'POST':
            Remark_count = request.POST['Remark_count']
            remarks = request.POST.getlist('remarks')
            added_by = CustomUser.objects.get(id=request.user.id)
            rid = request.POST['row_remark_id']
            get_demo = Demo_model.objects.get(pk=rid)
            new_remarks_list = []
            html_message = ''
            for remark in remarks:
                html_message += '<ul>'
                html_message += '<li>'
                html_message += f'Remark: {remark}<br>'
                html_message += '</li>'
                new_remarks_list.append(
                    {'demo_id': get_demo, 'remarks': remark, 'status': get_demo.status, 'added_by': added_by})
            html_message += f'</ul><br> above remark added to demo id {get_demo.id}<br> Added By: {added_by.email}'
            # new_remarks = Poc_remark()
            Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])
            messages.success(request, f'Demo remark added.')
            list_mail = []
            if request.user.role.name == "Approval":
                list_mail.append(request.user.email)

            else:
                list_mail.extend([request.user.email, request.user.Belongs_to.email])

            mail_for_action(f'New Remark Added for Demo id {get_demo.id}', html_message, list_mail)

            return redirect('view_demo_detail', id=id)
    except Exception as e:
        messages.error(request, f'Demo remark not added.', extra_tags="danger")
        return redirect('view_demo_detail', id=id)


@user_has_permission('add_feature')
@login_required(login_url='loginpage')
def add_demo_feature(request, id):
    try:
        if request.method == 'POST':
            added_by = CustomUser.objects.get(id=request.user.id)
            features_list = request.POST.getlist('Feature_ids')
            demo_ref = Demo_model.objects.get(pk=id)
            new_feature_list = []
            for j in features_list:
                new_feature_list.append({'demo_id': demo_ref, 'features_list': request.POST[f'features_{j}'],
                                         'timeline': request.POST[f'timeline_{j}'], 'status': 'Active',
                                         'added_by': added_by})
            features_lsts_added = []
            for data in new_feature_list:
                feature = Demo_feature.objects.create(**data)  # Create the Feature object
                status_data = Demo_Feature_status.objects.create(feature=feature, status="active",
                                                                 added_by=added_by)  # Create the Status object linked to the Feature
                features_lsts_added.append(status_data)

            html_ = ''' <div class="container">
            <h1>New Feature Added</h1>
            <p>A new feature has been added:</p>
            <ul>
              <li>Features: <span class="highlight">{", ".join(features_lsts_added)}</span></li>
              <li>Added By: <span class="highlight">{added_by.email}</span></li>
            </ul>
          </div>'''
            messages.success(request, f"New features: {','.join(features_lsts_added)} added successfully.")
            mail_for_action(f'New Feature Added for demo id {demo_ref.id}', html_,
                            [added_by.email, added_by.Belongs_to.email])

            return redirect('view_demo_detail', id=id)
    except Exception as e:
        messages.error(request, f"New features not added.", extra_tags="danger")
        return redirect('view_demo_detail', id=id)


@login_required(login_url='loginpage')
def get_detail_sts_demo(request):
    sts_data = dict()
    if request.method == 'POST':
        id = request.POST.get('id')
        feature = Demo_feature.objects.get(pk=id)
        get_data = Demo_Feature_status.objects.filter(feature=feature).order_by('-created_at')

        for data in get_data:
            sts_data[f'new_{data.id}'] = {'status': data.status, 'added_by': data.added_by.username,
                                          'time': data.created_at, 'feature': feature.features_list}
    return JsonResponse(sts_data)


@login_required(login_url='loginpage')
def demo_update_sts(request, id):
    if request.method == 'POST':
        try:
            sts_id = request.POST['sts_id']
            status = request.POST['status']
            added_by = CustomUser.objects.get(id=request.user.id)
            featureobj = Demo_feature.objects.get(pk=sts_id)
            Demo_Feature_status.objects.create(feature=featureobj, status=status, added_by=added_by)
            messages.success(request, f" Status: {status} added.")
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status  added.</h2> </div>')
        except Exception as e:
            messages.error(request, f"Status: {request.POST['status']} not added.", extra_tags="danger")
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2> status not added {e}.</h2> </div>')


@user_has_permission('edit_feature')
@login_required(login_url='loginpage')
def update_feature_detail_demo(request):
    if request.method == 'POST':
        try:
            id = request.POST['id']
            feature = get_object_or_404(Demo_feature, pk=id)
            get_demo = get_object_or_404(Demo_model, pk=feature.demo_id.id)
            if request.user.role.name == 'Sales' and get_demo.description:
                get_demo.status = Status.objects.get(name='Pending')
                get_demo.description = ''
                list_mail = [request.user.Belongs_to.email]
                mail_for_action(f'Project Request for Approve',
                                f' Project Request for Approve :- by {request.user.email}',
                                list_mail)
            get_demo.save()
            feature.features_list = request.POST['Feature_name']
            feature.status = request.POST['status']
            feature.timeline = request.POST['Feature_timeline']
            feature.added_by = CustomUser.objects.get(id=request.user.id)
            feature.save()
            list_mail = []
            if request.user.role.name == "Approval":
                list_mail.append(request.user.email)

            else:
                list_mail.extend([request.user.email, request.user.Belongs_to.email])
            html_ = '''<div class="container">
    <h1>Update Feature Detail</h1>
    <p>Here's the latest update on the feature:</p>
    <ul>
      <li>Features: <span class="feature">{feature.features_list}</span></li>
      <li>Status: <span class="feature">{feature.status}</span></li>
    </ul>
  </div>'''
            mail_for_action(f'Feature Updated:',
                            html_,
                            list_mail)
            messages.success(request, f"Feature : {feature.features_list} updated.")
            return HttpResponse(
                '<div class="messages text-center alert alert-success"> <h2>  updated.</h2> </div>')
        except Exception as e:
            messages.error(request, f"Feature not updated.", extra_tags="danger")
            return HttpResponse(
                f'<div class="messages text-center alert alert-danger"> <h2>  not updated {e}.</h2> </div>')


@user_has_permission('delete_feature')
def delete_feature(request):
    if request.method == 'POST':
        try:
            if request.POST['slug'] == 'demo':
                feature = get_object_or_404(Demo_feature, pk=int(request.POST['id']))  # Adjust model access logic
                name_of = feature.features_list
                feature.delete()
                get_demo = get_object_or_404(Demo_model, pk=feature.demo_id.id)
                if request.user.role.name == 'Sales' and get_demo.description:
                    get_demo.status = Status.objects.get(name='Pending')
                    get_demo.description = ''
                    list_mail = [request.user.Belongs_to.email]
                    mail_for_action(f'Project Request for Approve',
                                    f' Project Request for Approve :- by {request.user.email}',
                                    list_mail)
                get_demo.save()

                new_remarks_list = []
                new_remarks_list.append(
                    {'demo_id': get_demo, 'remarks': f"Feature deleted by {request.user.email}",
                     'status': get_demo.status, 'added_by': request.user})
                Demo_remark.objects.bulk_create([Demo_remark(**data) for data in new_remarks_list])

            else:
                feature = get_object_or_404(Feature, pk=int(request.POST['id']))  # Adjust model access logic
                name_of = feature.features_list
                feature.delete()
                get_poc = get_object_or_404(Poc_model, pk=feature.poc_id.id)
                if request.user.role.name == 'Sales' and get_poc.description:
                    get_poc.status = Status.objects.get(name='Pending')
                    get_poc.description = ''
                    list_mail = [request.user.Belongs_to.email]
                    mail_for_action(f'Project Request for Approve',
                                    f' Project Request for Approve :- by {request.user.email}',
                                    list_mail)
                get_poc.save()
                new_remarks_list = []
                new_remarks_list.append(
                    {'poc_id': get_poc, 'remarks': f"Feature - {name_of};  deleted by {request.user.email}",
                     'status': get_poc.status, 'added_by': request.user})
                Poc_remark.objects.bulk_create([Poc_remark(**data) for data in new_remarks_list])
            messages.success(request, f"Feature Deleted.")
            return JsonResponse({'success': True, 'message': 'Feature deleted successfully'})
        except Exception as e:
            messages.error(request, f"Feature  not deleted.", extra_tags="danger")
            return JsonResponse({'success': False, 'message': f'Error deleting feature: {e}'})
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method'})


@user_has_permission('approved_status')
def approved_status(request, pk, param1=None):
    try:
        if request.GET['param1'] in ['Accepted', 'Rejected'] and request.GET['param2'] in ['DEMO', 'POC']:
            if request.GET['param1'] == 'Accepted':
                status_nm = 'Approved'
            else:
                status_nm = 'Rejected'
            if request.GET['param2'] == 'POC':
                obj = Poc_model.objects.get(pk=pk)
                obj.status = Status.objects.get(name=status_nm)
                obj.description = ""
                obj.save()
                list_mail = [obj.added_by.email, request.user.email]
                mail_for_action(f'POC Request Approved',
                                f'POC Request id {obj.id}  is Approved<br> Approved from {request.user.email}',
                                list_mail)
                messages.success(request, f"Project Request {request.GET['param1']}.")
                return redirect('view_poc')
            if request.GET['param2'] == 'DEMO':
                obj = Demo_model.objects.get(pk=pk)
                obj.status = Status.objects.get(name=status_nm)
                obj.description = ""
                obj.save()
                list_mail = [obj.added_by.email, request.user.email]
                mail_for_action(f'Demo Request Approved',
                                f'Demo Request id {obj.id}  is Approved <br> Approved from {request.user.email}',
                                list_mail)
                messages.success(request, f"DEMO Request {request.GET['param1']}.")
                return redirect('view_demo')
        else:
            messages.error(request, f"Wrong Request!", extra_tags="danger")
            if request.GET['param2'] == 'POC':
                return redirect('view_poc')
            if request.GET['param2'] == 'DEMO':
                return redirect('view_demo')
    except Exception as e:
        messages.error(request, f"Something wrong!", extra_tags="danger")
        if request.GET['param2'] == 'POC':
            return redirect('view_poc')
        if request.GET['param2'] == 'DEMO':
            return redirect('view_demo')


def save_reject_desc(request):
    try:
        if request.POST:
            if request.POST['row__type'] == 'POC':
                obj = Poc_model.objects.get(pk=request.POST['row__id'])
                obj.status = Status.objects.get(name="Rejected")
                obj.description = request.POST.get('reason')
                obj.save()
                list_mail = [request.user.email, obj.added_by.email]
                messages.success(request, f'Project approval request Rejected.reason : {request.POST.get("reason")}')
                mail_for_action(f'Project approval request is Rejected',
                                f' Reason: {request.POST.get("reason")} <br> Customer: {obj.Customer_name.name}<br>'
                                f'<br>with product: {obj.Product_name.Product_name}<br>'
                                f'Rejected from {request.user.email}',
                                list_mail)
            elif request.POST['row__type'] == 'DEMO':
                obj = Demo_model.objects.get(pk=request.POST['row__id'])
                obj.status = Status.objects.get(name="Rejected")
                obj.description = request.POST.get('reason')
                obj.save()
                list_mail = [request.user.email, obj.added_by.email]
                messages.success(request, f'Demo approval request is Rejected. reason: {request.POST.get("reason")}')
                mail_for_action(f'Demo approval request is Rejected',
                                f' Reason: {request.POST.get("reason")} <br> Customer: {obj.Customer_name.name}<br>'
                                f'<br>with product: {obj.Product_name.Product_name}<br>'
                                f'Rejected from {request.user.email}',
                                list_mail)
            else:

                messages.error(request, 'Something Wrong with type of project!', extra_tags='danger')
        if request.POST['row__type'] == 'POC':
            return redirect('view_poc')
        elif request.POST['row__type'] == 'DEMO':
            return redirect('view_demo')
    except Exception as e:
        messages.error(request, f"Something Wrong!", extra_tags="danger")
        if request.POST['row__type'] == 'POC':
            return redirect('view_poc')
        elif request.POST['row__type'] == 'DEMO':
            return redirect('view_demo')


def save_permission(request, id):
    try:
        user = User.objects.get(pk=id)
        if request.method == 'POST':
            all_permission = CustomPermission.objects.all().order_by('id')
            if user.role.name == 'Admin':
                user.permissions.clear()
                for permissions in all_permission:
                    permission, _ = CustomPermission.objects.get_or_create(name=permissions)
                    user.permissions.add(permission)
                messages.success(request, f"Congratulation! you have full access for {app_name}!")
            else:
                messages.error(request, "You have no permission!", extra_tags='danger')
        return redirect('dashboard')
    except Exception as e:
        messages.error(request, f'Something Wrong!', extra_tags='danger')
        return redirect('dashboard')


@user_has_permission('manage_permissions')
def manage_permissions(request, id):
    context = {}
    context['all_permissions'] = CustomPermission.objects.all().order_by('id')
    context['users'] = User.objects.get(pk=id)
    if request.method == 'POST':
        user_id = request.POST.get('user')
        permissions = request.POST.getlist('permissions')
        # Retrieve the user based on the selected user_id
        user = CustomUser.objects.get(pk=user_id)
        # Clear existing permissions for the user and add selected permissions
        if user.role.name == 'Admin':
            user.permissions.clear()
            permission, _ = CustomPermission.objects.get_or_create(name="manage_permissions")
            user.permissions.add(permission)
        else:
            user.permissions.clear()
        for permission_name in permissions:
            if permission_name != "manage_permissions":
                permission, _ = CustomPermission.objects.get_or_create(name=permission_name)
                user.permissions.add(permission)
        # Save user permissions
        user.save()
        messages.success(request, "Permission Added.")
        return redirect('manage_permissions', id)
    # If GET request or form not submitted, render the permissions form
    return render(request, 'poc_demo/permissions.html', context)
