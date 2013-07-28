#!/usr/bin/python
"""
mostly a slight rewrite of yubico-yubiserve project.


"""

import re
import os
import sys
import sqlite3
from Crypto.Cipher import AES


class YubiKey(object):
    def __init__(self):
        dirpath = os.path.dirname(os.path.realpath(__file__))
        dbpath = dirpath + '/yubikeys.sqlite'
        self.conn = sqlite3.connect(dbpath)
        self.status = {'OK': 0, 'BAD_OTP': 1, 'REPLAYED_OTP': 2, 'DELAYED_OTP': 3, 'NO_CLIENT': 4}
        self.hex_chars = '0123456789abcdef'
        self.mod_chars = 'cbdefghijklnrtuv'

    def _hex2dec(self, _hex):
        return int(_hex, 16)

    def _modhex2hex(self, string):
        converted = ''
        for i in range(0, len(string)):
            _char = ''
            string_char = string[i]
            for n in range(0, len(self.mod_chars)):
                if string_char == self.mod_chars[n]:
                    _char = self.hex_chars[n]

            if _char == '':
                raise
            converted += _char
        return converted

    def _aes128ecb_decrypt(self, aeskey, aesdata):
        return AES.new(aeskey.decode('hex'),
                       AES.MODE_ECB).decrypt(aesdata.decode('hex')).encode('hex')

    def validate(self, otp):
        self.validationResult = 0
        self.OTP = re.escape(otp)

        if (len(self.OTP) <= 32) or (len(self.OTP) > 48):
            self.validationResult = self.status['BAD_OTP']
            return self.validationResult

        match = re.search('([cbdefghijklnrtuv]{0,16})'
                          '([cbdefghijklnrtuv]{32})', self.OTP)
        cur = self.conn.cursor()
        try:
            if match.group(1) and match.group(2):
                self.userid = match.group(1)
                self.token = self._modhex2hex(match.group(2))
                cur.execute('SELECT aeskey, internalname FROM yubikeys WHERE publicname = "'
                            + self.userid + '" AND active = "1"')
                if cur.arraysize != 1:
                    self.validationResult = self.status['BAD_OTP']
                    return self.validationResult
                (self.aeskey, self.internalname) = cur.fetchone()

                self.plaintext = self._aes128ecb_decrypt(self.aeskey, self.token)
                self.uid = self.plaintext[:12]

                if self.internalname != self.uid:
                    self.validationResult = self.status['BAD_OTP']
                    return self.validationResult

                # Here the original did some weird crc checking
                # Gonna skip that for now and come back to it later
                # TODO: crc checking

                self.internalcounter = self._hex2dec(self.plaintext[14:16] +
                                                     self.plaintext[12:14] +
                                                     self.plaintext[22:24])
                self.timestamp = self._hex2dec(self.plaintext[20:22] +
                                               self.plaintext[18:20] +
                                               self.plaintext[16:18])

                sql = 'SELECT counter, time FROM yubikeys WHERE ' \
                      'internalname = "%s" AND active = "1";' % self.uid
                cur.execute(sql)

                if cur.arraysize != 1:
                    self.validationResult = self.status['BAD_OTP']
                    return self.validationResult
                (self.counter, self.time) = cur.fetchone()

                if self.counter >= self.internalcounter:
                    self.validationResult = self.status['REPLAYED_OTP']
                    return self.validationResult

                if (self.time >= self.timestamp) and \
                        ((self.counter >> 8) == (self.internalcounter >> 8)):
                    self.validationResult = self.status['DELAYED_OTP']
                    return self.validationResult

        except IndexError:
            self.validationResult = self.status['BAD_OTP']
            return self.validationResult

        except AttributeError:
            self.validationResult = self.status['BAD_OTP']
            return self.validationResult

        self.validationResult = self.status['OK']
        cur.execute('UPDATE yubikeys SET counter = ' +
                    str(self.internalcounter) +
                    ', time = ' + str(self.timestamp) +
                    ' WHERE internalname = "' + self.uid + '"')
        self.conn.commit()
        return self.validationResult


def main():
    otp = YubiKey()
    validation = otp.validate(sys.argv[1])
    sys.exit(validation)


if __name__ == '__main__':
    main()
