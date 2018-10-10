'use strict';

const {create, env} = require('sanctuary');
const $ = require('sanctuary-def');
const {env: flutureEnv} = require('fluture-sanctuary-types');
const Future = require('fluture');
const S = create({checkTypes: true, env: env.concat(flutureEnv)});
const et = require('expect-telnet');
const fs = require('fs');

const read = Future.encaseN2(fs.readFile);
const readTextFile = filename =>
  read(filename, 'utf-8')
  .map(S.lines)

//tryPassword :: String -> String -> Future String StrMap
const tryPassword = ip => pass => Future(function computation(reject, resolve) {
  et(ip + ":23", [
    { expect: "Password:", send: pass + '\r'},
    { expect: /#|>/, send: 'exit\r', out: () => resolve({ip, password: pass})}
  ], err => {
    if(err !== undefined){
        reject(err.message);
    }
  });
});

//tryPasswords :: [String] -> String -> Future String StrMap
const tryPasswords = passwords => ip =>
  passwords.length === 0
    ? Future.reject(`No password found for ${ip}`)
    : tryPassword (ip) (passwords[0])
      .chainRej(res =>
        S.equals ("Expect sequence timeout: /#|>/") (res) === true
          ? tryPasswords(passwords.slice(1)) (ip)
          : Future.reject(res)
      )

// tryPasswordsOnIps :: ([String] -> String -> Future String StrMap) -> [String] -> [String] -> [Future]
const tryPasswordsOnIps = passExtractionFunction => ips => passwords =>
  S.map (ip =>
    passExtractionFunction (passwords) (ip)
  ) (ips)


//stringReducer :: String -> String -> String
const stringReducer = str => elem => str += elem;

Future.both(
  readTextFile('./ips'),
  readTextFile('./passwords')
)
.chain(([ips, passwords]) => {
    const listOfDevicePasswordFutures = tryPasswordsOnIps (tryPasswords) (ips) (passwords);
    const stabalizedListOfDevicePasswordFutures = S.map (Future.fold(S.Left, S.Right)) (listOfDevicePasswordFutures);
    return Future.parallel(Infinity, stabalizedListOfDevicePasswordFutures)
  })
.fork(
  console.error,
  res => {
    const found = S.pipe([
      S.filter(S.isRight),
      S.map(S.fromEither({})),
      S.map(obj => `${S.prop('ip') (obj)},${S.prop('password') (obj)}\n`),
      S.reduce(stringReducer) ('')
    ]) (res);
    const errors = S.pipe([
      S.filter(S.isLeft),
      S.map(S.either(S.I) (S.I)),
      S.map(S.concat('\n')),
      S.reduce(stringReducer) ('')
    ]) (res);
    console.log(`Devices with discovered passwords: \n${found}`);
    console.log(`Reported errors: ${errors}\n`);
});


//urobit distribution kolko krat najdem passwords a stale zoradit hesla podla toho
