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
We can see the secret is generated using one of our login inputs:

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

One other odd thing, it seems the challenge is hosted on `IIS/8.0` - this means
we're attacking a Windows OS. This is weird for a server which are almost
exclusively Linux based using Nginx or Apache. I'm sure it's not relevant...

## 0x01 Windows Defender? More like Windows Defendon't

We can't brutforce `SALT` and `PEPPER` (I know, I tried for 3hrs), so we need to
find a way to leak the secret itself or some crypto dark magic to make a
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
docker exec -it my-apache-php-app ls -al /tmp
```

We can see a PHP created a session file at `/tmp/sess_*`:
```
drwxrwxrwt 1 root     root     4096 Sep  5 00:45 .
drwxr-xr-x 1 root     root     4096 Sep  5 00:44 ..
-rw------- 1 www-data www-data   98 Sep  5 00:45 sess_9bbcc104b32fbcac0edafd9cb0432991
```
Reading the file:
```
docker exec -it my-apache-php-app cat /tmp/sess_9bbcc104b32fbcac0edafd9cb0432991
```

We can see what a PHP session looks like:
```
realname|s:14:"Hello There...";nickname|s:14:"General Kenobi";secret|s:32:"742de24238d4adc573b03a2b3589c5e5";
```

This is exactly what a Defender leak needs! A file on disk that gets read per
user request which contains user controlled data and some secret we want to get
our hands on.
