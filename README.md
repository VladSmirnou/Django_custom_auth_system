# Django auth system rewritten with forms instead of using built-in classes

## The purpose
The main puprose is to understand on a bit lower level how Django auth system was implemented.

## Installation
```
Manually:
  Install requirements.txt
  Set environment variables from .env-template
  Migrate DB 
  Smtp backend is enabled by default, so change it first if you don't want to send a real email
  PostgreSQL backends activated by default, comment it out and uncomment SQLite backends if you want to
Docker compose:
  Set environment variables from .env-template
  Run docker compose command
```
## Features 
```
User signs up with an email instead of a username
User can check if its password(s) was pwned or not
User can reset its email without knowing the old one
Docker compose support
```
## Features review
- For the password check I'm using https://haveibeenpwned.com/ API. A user can check
one password or at most ten passwords at a time. For the bulk password check i'm using httpx async request.
Ratelimit exists for those two views, so its possible to GET them as many times as you
want, but POST request is limited to 1/m.
- For the email reset i'm using a system that i created from scratch just to have some fun.
When a user signs up for the first time, it receives a normal email verification link and a PDF file that contains a 
base text token (visible) and an encrypted hidden token (invisible), that is weaved into this file structure (super simple cryptography + steganography), so it is pointless to guess only visible token. 
This info is connected to the user, so if it has forgotten its email and password it is still possible to reset them
using this file.
After email reset the new PDF file is generatred and the old one is no longer valid.

## Quick note
I didn't properly test email reset feature, because i didn't even want to add it, i just got an idea at the last moment. Now
i have more important things to do. Especially scary part is where i read a file that a user uploaded, it must be testet better than anything.

Password check is not tested either, because i lost all the time creating email reset stuff. (quite smooth excuse isn't it?).
I'd use mock for those tests tho. Maybe i'll do that later.

During this project i figured out that Django dev server is multi-threaded and fn-based view (that i use here) is not thread
safe, so a race condition can occur. It was too late to fix this. Only bulk password check is protected with lock.

There are 100% functions that shouldn't be cached, prolly that post sensitive data (i saw Django uses '@never_cache' dec and another stuff with some functions), but i don't know yet what i should and shoudn't cache.