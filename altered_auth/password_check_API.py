import asyncio
import hashlib

import httpx

# it's https://haveibeenpwned.com/ API, i'm using searching by range, 
# because it doesn't use a raw password

# How this API works ->
# I send the first 5 characters of a hashed password (must be SHA1 hash) to the API,
# it returns a list of bytestrings, where those 5 characters match.
# This list contains THE REMAINDER (my hashed password[5:]) of the hashed 
# password and the amount of times this remainder was pwned, separated by a colon,
# like -> b'HASH_REMAINDER:pwned_count'
# i need to check if there is a remainder in this list, that matches 
# the tail of my hashed password [5:]. If it is, i need to get the amount of times it was
# pwned.
# API input is not case-sensitive, but output is always in upper case.

def simple_password_check(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_chars, remainder = hashed_password[:5], hashed_password[5:]

    url = f'https://api.pwnedpasswords.com/range/{first_five_chars}'
    res = httpx.get(url)

    if res.status_code != 200:
        # i need to return something except int(500) here, because there is can be a password
        # that was hacked exactly 500 times
        return '500' 

    string_gen = (string.split(':') for string in res.text.splitlines())
    for tail, pwned_count in string_gen:
        if tail == remainder:
            return pwned_count

    return 0


async def bulk_password_check(list_of_first_chars):
    async with httpx.AsyncClient() as client:
        tasks = (client.get(f'https://api.pwnedpasswords.com/range/{hashes}') for hashes in list_of_first_chars)
        try:
            # need to apply a timer here, because if there is no responce, this view will end up in a dead lock
            res = await asyncio.wait_for(asyncio.gather(*tasks), 3)
        except asyncio.TimeoutError:
            yield 500

    for response in res:
        if response.status_code != 200:
            yield 500

    list_of_lists_of_hashes = (string.text.splitlines() for string in res)
    for list_of_hashes in list_of_lists_of_hashes:
        yield list_of_hashes


async def main(passwords):
    # check, if there are copies in an input
    if len(set(passwords)) != len(passwords):
        return 

    list_of_first_chars = []
    remainders = {}
    for password in passwords:
        hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first_five_chars, remainder = hashed_password[:5], hashed_password[5:]
        list_of_first_chars.append(first_five_chars)
        remainders[remainder] = password

    pwned_passwords = {}
    async for list_of_hashes in bulk_password_check(list_of_first_chars):
        if list_of_hashes == 500:
            return 500
        for hashed_pass in list_of_hashes:
            if remainders.get(tail:= hashed_pass.split(':')[0]):
                pwned_passwords[remainders[tail]] = hashed_pass.split(':')[1]

    return pwned_passwords
