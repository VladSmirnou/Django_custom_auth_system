import random
import string
import uuid

import PyPDF2
from fpdf import FPDF

from django.contrib import messages
from django.core.mail import EmailMessage
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import get_user_model

from .models import UserEmailRestorationData


def cleaner(request, success=False):
    del request.session['encoded_user']
    del request.session['token']
    if success:
        messages.success(request, 'Your password was successfully changed, you\'re now able to log in.')
    else:
        messages.error(request, 'Activation link is invalid. Try again.')


def token_exists(request):
    try:
        token = request.session['token']
    except KeyError:
        return 
    return token


def link_check(uidb64, token, email_ver=False):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_user_model().objects.get(pk=uid)
    except:
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        # i can write this line like this -> 'not email_ver or user' but it is hard to read
        return True if not email_ver else user
    return 


def pdf_creator(user):
    text_token = str(uuid.uuid4())

    base_token_string = uuid.uuid4()
    user_personality_salt = user.personal_info.lower()
    initial_string = str(base_token_string).replace('-', '') + user_personality_salt
    lower_digits = string.ascii_lowercase + string.digits
    list_lower_digits = list(lower_digits)
    random.shuffle(list_lower_digits)

    pattern = str.maketrans(lower_digits, ''.join(list_lower_digits))
    user_token = str.translate(initial_string, pattern)
    secret_key = {v: k for k, v in pattern.items()}
    # According to Django docs 'update_or_create' method doesn't fit here, because there are no unique constraints
    # applied and concurrent calls may occur. Can fix with lock, but performance may suffer.
    UserEmailRestorationData.objects.create(
        custom_user=user,
        text_token=text_token,
        initial_string=initial_string,
        secret_key=secret_key
    )

    # creates a PDF file on the fly
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Times', size=20)
    
    pdf.cell(200, 10, txt=text_token, ln=1, align='C')
    bytestring_pdf = pdf.output(dest='S').encode('latin-1')

    completed_pdf = bytestring_pdf + user_token.encode('latin-1')

    return completed_pdf


def email_sender(request, user):
    message = render_to_string('email_reset/user_email_verification.html', {
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
        'protocol': "https" if request.is_secure() else "http" 
        }
    )

    email = EmailMessage(
        subject='Email verification',
        body=message,
        to=[user.email,],
    )

    email.attach(
        filename='private_token.pdf',
        content=pdf_creator(user), # console shows this file as a base64 encoded string
        mimetype='application/pdf'
    )

    email.send()


def decrypt_hidden_token(file, user):
    content = file.read()
    offset = content.index(bytes.fromhex('0A2525454F460A'))
    file.seek(offset + 7)
    hidden_token = file.read()
    
    if not hidden_token or len(hidden_token) > 52:
        return 

    try:
        decoded_token = hidden_token.decode('latin-1')
    except UnicodeDecodeError:
        return 

    user_secret_key = user.useremailrestorationdata.secret_key
    user_initial_string = user.useremailrestorationdata.initial_string

    secret_key = {int(v): k for v, k in user_secret_key.items()} 
    decrypted_token = decoded_token.translate(secret_key)
    
    if decrypted_token == user_initial_string:
        return True
    
    return 


def assert_user_credentials(file, personal_info):
    # if someone rewrites a token in a file, then i'll have an error
    try:
        reader = PyPDF2.PdfReader(file)
        page1 = reader.pages[0]
        text_token = page1.extract_text()
        user = get_user_model().objects.get(
            useremailrestorationdata__text_token=text_token,
            personal_info=personal_info
        )
    except:
        return
    else:
        file.seek(0)
        if decrypt_hidden_token(file, user):
            return user
        return 
    finally:
        file.close()
