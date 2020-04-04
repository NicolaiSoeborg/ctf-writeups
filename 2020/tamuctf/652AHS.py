```
$ printf '2\nNo\nNo\nYes\nYes\nNo\nYes\nNo\nYes\nNo\nNo\nYes\nNo\nYes\nNo\nYes\nYes\nYes\nNo\nYes\nYes\n\xFF\n' | nc challenges.tamuctf.com 7393
Welcome admin. Select an option:

	1. Enter password
	2. Reset password
	3. Exit
--------------------------
      Password Reset      
--------------------------
Please answer the following yes/no security questions to prove your identity. Type either "Yes" or "No" for each (without quotation marks).
Does pineapple belong on pizza?
Do you read for fun?
Are you scared of the dark?
Do you like tea?
Is Coke better than Pepsi?
Are parrots more fun than chimpanzees?
Is December your favorite month?
Have you ever seen the rain?
Would you rather fight one hundred duck-sized horses than one horse-sized duck?
Is it ever okay to lie?
Have you ever been in an earthquake?
Do you sleep on your side?
Have you traveled outside of the country?
Is Star Wars better than Star Trek?
Are long nights better than early mornings?
Do you prefer your water with ice?
Is happiness a choice?
Are a few close friends better than many average friends?
Do you have kids?
Is it better to be bold or welcoming?
New password:
gigem{t1ck_t0cK_toCk_t111ck_tiCK_tockk}
```



    #print(tn.read_until(b'?\n').decode())
    #tn.write(b"\xFF\n")
    #for _ in range(15): print(tn.read_some().decode(), end="")
    """
  File "/crypto/server.py", line 92, in <module>
    run_server()
  File "/crypto/server.py", line 88, in run_server
    options[option-1]() # sneak
  File "/crypto/server.py", line 67, in reset
    good = good and check(answer, answer_hash)
  File "/crypto/server.py", line 19, in check
    good = good and (encrypt(plaintext) == ciphertext)
  File "/crypto/server.py", line 9, in encrypt
    return hashlib.sha256(plaintext.encode()).hexdigest()
UnicodeEncodeError: 'utf-8' codec can't encode characters in position 0-1: surrogates not allowed
    """

    #tn.write(b"\xFF\n")
    #for _ in range(15):
    #    print(tn.read_some().decode(), end='')
    """
Traceback (most recent call last):
  File "/crypto/server.py", line 92, in <module>
    run_server()
  File "/crypto/server.py", line 88, in run_server
    options[option-1]() # sneak
  File "/crypto/server.py", line 46, in login
    if check(password, pw_hash):
  File "/crypto/server.py", line 19, in check
    good = good and (encrypt(plaintext) == ciphertext)
  File "/crypto/server.py", line 9, in encrypt
    return hashlib.sha256(plaintext.encode()).hexdigest()
UnicodeEncodeError: 'utf-8' codec can't encode characters in position 0-1: surrogates not allowed
    """
    
