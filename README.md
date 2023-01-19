Django auth system rewritten with forms instead of using built-in classes.
The puprose is to understand how it was implemented on a bit lower level.

There is also an additional feature, that allows a user to check if its password
was pwned or not. I'm using 'https://haveibeenpwned.com/' API for it. User can check
one password or at most 10 passwords at a time.
For bulk password check i'm using httpx async request.
Ratelimit exists for those two views, so its possible to GET them as many times as you
want, but POST request is limited to 1/m.

This project is still in development, so it's not cleaned up.