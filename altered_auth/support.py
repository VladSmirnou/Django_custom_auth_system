from django.contrib import messages


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
        return False
    return token
