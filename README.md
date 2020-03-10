# The сryptopals challenges solutions

These are my solutions to the infamous [cryptopals challenges](https://cryptopals.com/).

##  How to use this code

The solutions to the challenges are designed as tests and could be found in the files with names in the form `[set#]_[challenge#]_[short_description]_test.go`.

This project was not meant to be be `require`d.
To run the solutions simply clone this repository to a local directory and run from its root:
```
go test -v cryptopals/cryptopals
```

This should run all the tests (i.e. challenges solutions) at once but you probably don't want to do.
To run the solution to a specific challenge look for its test name in the corresponding {{*_test.go}} file and run it with:
```
go test -v cryptopals/cryptopals -run TestPkcs15PaddingOracleAttack
```

## Notes

In the [description](https://cryptopals.com/) to the challenges you can find this suggestion:

> Our friend Maciej says these challenges are a good way to learn a new language, so maybe now's the time to pick up Clojure or Rust.

I had wanted to check out Go for some time so I skipped through the tour of Go, glanced through the stdlib to make sure I wouldn't have to implement something like big number arithmetic myself and set to work. So while the code for every next challenge is hopefully a more idiomatic Go than for the previous one, keep in mind this was the first time I used the language.

I hope the code is readable and I commented the difficult to understand parts but this is not the kind of project you write a highly maintainable code so expect a code quality typical for a "proof of concept".

When going through the challenges I had to pause to read up on the number theory. If you need to brush up the math on the topic too I highly recommend "The Mathematics of Ciphers: Number Theory and RSA Cryptography".
