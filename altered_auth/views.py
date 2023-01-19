from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout
from django.views.generic import CreateView
from .forms import CustomUserCreationForm, PasswordCheckForm, BulkPasswordCheckForm
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (
    AuthenticationForm, 
    PasswordChangeForm, 
    PasswordResetForm,
    SetPasswordForm,
    # UserCreationForm 
    )
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib import messages
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from altered_auth_core import settings
from django.http import Http404, HttpResponse, HttpResponseForbidden
from django.views.decorators.http import require_http_methods
from .support import cleaner, token_exists
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from .password_check_API import main, simple_password_check
import time
from django_ratelimit.decorators import ratelimit, Ratelimited
import asyncio


@require_http_methods(['GET'])
def home_page(request):
    return render(request, 'home.html')


# maybe, if i have time, i'll rewrite this one by myself, with a password hashing, etc.
class SignUpView(CreateView):
    # Only not authenticated users can access.
    form_class = CustomUserCreationForm
    success_url = reverse_lazy('login')
    template_name = 'registration/signup.html'


@require_http_methods(['GET', 'POST'])
def login_view(request):
    # Added because i want to login a user with an email instead of a username
    # think about add registration with a username and an email
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            # i'm not using authenticate() method here cus
            # AuthenticationForm class already has clean() method
            # and does call authenticate() during .is_valid() check
            user = get_object_or_404(
                get_user_model(),
                email=form.cleaned_data.get('username') # try to fix 'username' to 'email'
            )
            login(request, user)
            return redirect('home')

    else:
        if request.user.is_authenticated: 
            messages.error(request, 'You are already logged in, logout first if you want to change an account')
            return redirect('home')
        form = AuthenticationForm()

    return render(request, 'registration/login.html', {'form': form})


@require_http_methods(['GET'])
def logout_view(request):
    if request.user.is_authenticated:
        logout(request)
        return redirect('home')
    messages.error(request, 'You have to be logged in')
    return redirect('home')


@login_required(login_url='login')
@require_http_methods(['GET', 'POST'])
def password_change(request):
    # Added because i want to logout a user after password change
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            return redirect('password-change-done')

    else:
        form = PasswordChangeForm(user=request.user)

    return render(request, 'registration/password_change_form.html', {'form': form})


def password_change_done(request):
    # i need this method, because if i render a 'password_change_done' template from 
    # the 'password_change' view and refresh the page, it will send a new
    # POST request. Because i don't use 'update_session_auth_hash()' a user is now logged out.
    # if i remove '@login_required' decorator it will error out in 'user.check_password' line.

    # I can leave '@login_required' and render this html page from 'password_change', and 
    # on the second request it will ask if a user wants to resubmit the form. If a user agreed 
    # it would redirect to the 'login' page because a user is now logged out. It's pretty hard to
    # understand why it works like this and make a user guess about why the server asks it to
    # resubmit the form again.
    return render(request, 'registration/password_change_done.html')


@require_http_methods(['GET', 'POST'])
def password_reset(request):
    if request.method == 'POST':
        form = PasswordResetForm(data=request.POST)
        # This form is always valid, but 'save' method needs 'clean_data' dictionary,
        # so i have to check it anyways
        if form.is_valid():
            form.save(
                email_template_name="password/password_reset_email.html",
                use_https=True if request.is_secure() else False,
                request=request
            )
            return redirect('password-reset-done')
    
    form = PasswordResetForm()

    return render(request, 'password/password_reset.html', {'form': form})


def password_reset_done(request):
    # i need this method, because if i render a template from 
    # 'password_reset' view and refresh the page, it will send a new
    # POST request and generate a new link
    return render(request, 'password/password_reset_done.html', {
        'lifespan': int(settings.PASSWORD_RESET_TIMEOUT/60)
        }
    )


@require_http_methods(['GET'])
def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except:
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['encoded_user'] = uidb64
        request.session['token'] = token
        return redirect('password_reset_complete')

    # this 'try' block cleanes old session token and uid. 
    # It is not rly neccessary, but i wanna make sure that
    # there is no stale data flying around

    # if a user didn't click a link at all before it expired,
    # or someone is trying to hardcode uid and token
    # there will be no data to clean, so KeyError occurs and
    # i need to add a message specifically for this case
    try:
        cleaner(request)
    except KeyError:
        messages.error(request, 'Activation link is invalid. Try again')
    return redirect('home')


@require_http_methods(['GET','POST'])
def password_reset_complete(request):
    if request.method == 'POST':
        # i need this 'try' block, because if someone opens two tabs with
        # the password change form, turns both of them into this POST
        # fork and submit one of them, on the second submit there will be no token,
        # and it will error out
        if token:= token_exists(request):
            # if there is no token it means that there is no user as well. So i can remove this
            # user query from 'try' block
            user = get_user_model().objects.get(email=request.POST.get('user'))
            # i need to check if a token expired on POST fork as well
            if default_token_generator.check_token(user, token):
                form = SetPasswordForm(user=user, data=request.POST)
                if form.is_valid():
                    form.save()
                    cleaner(request, success=True)
                    return redirect('login')
            else:
                cleaner(request)
                return redirect('home')
        else:
            raise Http404()

    else:
        # if someone's trying to get this URL by manualy typing it, or opened two tabs,
        # submitted the form and changed a password. After page refresh it will error out because
        # there is no token anymore
        if token:= token_exists(request):
            # if there is no token it means that there is no user as well. So i can remove this
            # user query from 'try' block. 
            user = get_user_model().objects.get(
                        pk=urlsafe_base64_decode(request.session['encoded_user']).decode()
                    )
            # if a user didn't set any password and trying to refresh the page, or 
            # get it by a direct url (if it saved this tab somewhere) with the token that expired,
            # i can clean his data and send an error message, because the link is no longer valid
            if default_token_generator.check_token(user, token):
                form = SetPasswordForm(user=user)
            else:
                cleaner(request)
                return redirect('home')
        else:
            raise Http404()

    return render(request, 'password/password_reset_complete.html', {'form': form, 'user': user})


@csrf_exempt
@ratelimit(key='user_or_ip', rate='1/m', method=['POST'])
def password_security_check(request):

    # Without rate limit someone can actually DDOS this API from
    # this form. It will DDOS this server and the API at the same time,
    # and the API owner might block this server IP address. 
    # Why not to DDOS it directly? Maybe this is a key feature of two diff
    # companies and one of them decided to remove its rival 
    # or, at least, cause some troubles.

    if request.method == 'POST':
        form = PasswordCheckForm(request.POST)
        if form.is_valid():
            password_to_check = form.cleaned_data.get('password')
            try:
                validate_password(password_to_check) # First i need to validate a password as Django validates it
            except ValidationError as err: 
                form.add_error('password', err)
            else:
                if (value:= simple_password_check(password_to_check)) == 0: # API call
                    messages.success(request, f'Password [ {password_to_check} ] was hacked 0 times, congrats!')
                else:
                    messages.error(request,
                    'Server is currently unavailable' if value == '500' else f'Password \
                        [ {password_to_check} ] was hacked {value} times, consider to make it stronger!'
                )

    else:
        form = PasswordCheckForm()

    return render(request, 'password_check_feature/password_check_form.html', {'form': form})


@csrf_exempt
@ratelimit(key='user_or_ip', rate='1/m', method=['POST'])
def bulk_password_security_check(request):
    pwned_passwords = {}
    if request.method == 'POST':
        form = BulkPasswordCheckForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            for password in list(data):
                try:
                    validate_password(data[password])
                except ValidationError as err: 
                    form.add_error(password, err)
            if not form.errors:
                start = time.time()
                if isinstance(values:= asyncio.run(main(data.values())), dict):
                    pwned_passwords = values
                    if not pwned_passwords:
                        messages.success(request, 'Congrats! All passwords are solid.')
                else: 
                    messages.error(request,
                    'Server is currently unavailable.' if values == 500 else 'There is a copy or copies in your passwords, \
                        all passwords must be unique.'
                )
                end = time.time()
                print(end - start)

    else:
        form = BulkPasswordCheckForm()
    return render(
        request,
        'password_check_feature/bulk_password_check_form.html', {
            'form': form,
            'pwned_passwords': pwned_passwords or None
            }
        )


def handler403(request, exception=None):
    if isinstance(exception, Ratelimited):
        return render(request, '403error_redirect.html', status=429)
    return HttpResponseForbidden('Forbidden')