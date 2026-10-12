"""Offline list of widely known compromised/common passwords (SEC-PWD-003, partial).

This is a compact baseline that works without network access. A k-anonymity breach
lookup (e.g. Have I Been Pwned range API) can be enabled in M20 where outbound
access is permitted.
"""

_GLOBAL = """
123456 123456789 12345678 password qwerty 12345 1234567 111111 123123 1234567890
000000 abc123 password1 iloveyou 1q2w3e4r 1q2w3e4r5t qwerty123 qwertyuiop 654321 666666
121212 123321 987654321 112233 159753 7777777 88888888 55555555 11111111 00000000
admin admin123 administrator root letmein welcome welcome1 monkey dragon football
baseball sunshine princess master shadow superman michael charlie jordan jennifer
trustno1 passw0rd p@ssw0rd p@ssword password123 password12 pass1234 changeme secret
login hello hello123 freedom whatever starwars batman zaq12wsx asdfghjk asdfgh
asdf1234 1qaz2wsx qazwsx zxcvbnm zxcvbn computer internet google samsung iphone
nokia apple blackberry football1 soccer liverpool chelsea arsenal manchester barcelona
realmadrid ronaldo messi 147258369 123654 789456123 456789 1234qwer qwer1234
abcd1234 aa123456 a123456 a1b2c3d4 test test123 testing guest default user
"""

# Common local choices in Tanzania / East Africa.
_LOCAL = """
tanzania tanzania1 tanzania123 bongo bongo123 bongoflava daressalaam dar123 arusha
arusha123 mwanza dodoma zanzibar kilimanjaro serengeti simba simba123 yanga yanga123
yangaafrica simbasc mungu mungu123 mungumwema yesu yesu123 yesunibwana allah allah123
mama mama123 mamayangu baba baba123 babayangu upendo upendo123 amani amani123 baraka
baraka123 neema neema123 rehema furaha tumaini imani pendo nakupenda nakupenda123
jambo jambo123 karibu karibu123 asante hakunamatata swahili kiswahili mpesa mpesa123
vodacom tigo airtel halotel sokoni kariakoo kariakoo123 bongomarkets bongomarket
"""

COMMON_PASSWORDS: frozenset[str] = frozenset((_GLOBAL + _LOCAL).split())
