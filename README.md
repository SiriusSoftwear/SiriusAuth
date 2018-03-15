# SiriusAuth
A lightweighted library to provide easy access to time-based one-time passwords (TOTP).
The library itself is very easy and intuitive to use.
## Build options
First you need to initiate the SiriusAuth object.

```SiriusAuth siriusAuth= new SiriusAuth.Builder().build()```

This is the most basic way to initiate the SiriusAuth object.
Here are more options to specify the SiriusAuth object.

```SiriusAuth siriusAuth= new SiriusAuth.Builder().Key(String key).build()```

You can hand a specific key you want to use. (a new key will be generated by standard)

```SiriusAuth siriusAuth= new SiriusAuth.Builder().KeyLength(int length).build()```

You can specify the length of a new generated key. (standard key length is 32)

```SiriusAuth siriusAuth= new SiriusAuth.Builder().Algorithm(String algorithm).build()```

You can change the used hashing algorithm. (standard algorithm is MD5)

```SiriusAuth siriusAuth= new SiriusAuth.Builder().Digits(int digits).build()```

You can change the digits of the time-based one-time password (standard digits are 6)
## Usage
