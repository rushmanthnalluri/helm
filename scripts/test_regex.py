import re
raw = 'Open WhatsApp and send Hi to Guru Charan K.L.U.'
clean = raw.strip()
m1 = re.search(r'^(?:open\s+)?(whatsapp|telegram)\s+(?:and\s+|to\s+)?(?:say|send|text|message)\s+(.+?)\s+to\s+(.+)$', clean, re.I)
if m1:
    print('app:', m1.group(1))
    print('message:', m1.group(2))
    print('recipient:', m1.group(3))
else:
    print('No match')
