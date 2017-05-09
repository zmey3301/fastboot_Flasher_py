#!/usr/bin/python3
import os, sys, subprocess, time, pyparsing as ppa, pycurl, zipfile, hashlib, certifi, urllib3
from termcolor import colored
from io import BytesIO
filesApprooved = []
firmwarev = None
data = {'file': 'userdata.img', 'part': 'userdata'}
recovery = {'file': 'recovery.img', 'part': 'recovery'}
extraParts = [{'in': 'NON-HLOS', 'out': 'modem'}, {'in': 'emmc_appsboot', 'out': 'aboot'}, {'in': 'adspso', 'out': 'dsp'}]
if sys.platform == 'win32':
    import colorama
    colorama.init()
def cls():
    os.system('cls' if os.name=='nt' else 'clear')
def errormesg(errinfo, errcode):
    print (colored("!!", "red", attrs=["bold", "blink"]) + colored(" Ошибка: " + str(errinfo), "red", attrs=["bold"]) + colored(" !!", "red", attrs=["bold", "blink"]))
    print ("Выполнение скрипта было остановлено, код ошибки " + str(errcode) + ". Устраните проблему и попробуйте снова.")
    input()
    sys.exit(errcode)
def downloader(mode, dev):
    def progress(download_t, download_d, upload_t, upload_d):
        if download_t != 0:
            percent = round(100 * (download_d / download_t), 1)
            print('Загружаем ' + colored(filesApprooved[firmwarev]['file'], 'green', attrs=['bold']) + ' ' + colored(str(percent) + '%', attrs=['bold']), end='\r')
    buffer = BytesIO()
    def testConn():
        http = urllib3.PoolManager()
        try:
            r = http.request('GET', downloadConfigUrl)
            if r.status == 200:
                return True
            else:
                errormesg('Запрос к серверу вернул ошибку ' + str(r.status), 40000 + r.status)
        except urllib3.exceptions.HTTPError as err:
            return False
    if testConn() != True:
        errormesg('Нет соединения с с сервером', 42)
    c = pycurl.Curl()
    c.setopt(pycurl.CAINFO, certifi.where())
    c.setopt(c.URL, downloadConfigUrl)
    c.setopt(c.WRITEDATA, buffer)
    c.perform()
    c.close()
    downloads = buffer.getvalue().decode(sys.stdout.encoding).split('\n')
    downloadParse = (ppa.Word(ppa.alphas + '-_'))('device') + (ppa.Word(ppa.alphanums + '-_.()'))('filename') + (ppa.Word(ppa.alphanums))('hashes') + (ppa.Word(ppa.alphanums + '-_./\():'))('link')
    while downloads.count('') > 0:
        downloads.remove('')
    filesinfo = []
    for files in downloads:
        filesinfo.append({'device': downloadParse.parseString(files).device,
                          'file': downloadParse.parseString(files).filename,
                          'hash': downloadParse.parseString(files).hashes,
                          'link': downloadParse.parseString(files).link})
    test = 0
    global filesApprooved
    for files in filesinfo:
        if dev == files['device'].lower():
            if mode in files['file'].lower():
                filesApprooved.append({'file': files['file'],
                                       'hash': files['hash'],
                                       'link': files['link']})
                test += 1
    if test == 0:
        errormesg('Нет подходящих файлов для загрузки', 46)
    i = 0
    for files in filesApprooved:
        print (colored(str(i + 1) + ') ', 'green', attrs=['bold']) + files['file'])
        i += 1
    firmwarev = input('Выберите прошивку (' + colored('[1]', 'green', attrs=['bold']) + '): ')
    if firmwarev == '':
        firmwarev = 0
    elif int(firmwarev) > 0:
        firmwarev = int(firmwarev) - 1
    hashOn = input('Проверять MD5 сумму? (' + colored('[y]', 'green', attrs=['bold']) + '/n): ')
    hashOn = hashOn.lower()
    if hashOn == 'т':
        hashOn = 'n'
    hashErr = None
    while hashErr != False:
        with open(filesApprooved[firmwarev]['file'], 'wb') as f:
            c = pycurl.Curl()
            c.setopt(pycurl.CAINFO, certifi.where())
            c.setopt(c.URL, filesApprooved[firmwarev]['link'])
            c.setopt(c.WRITEDATA, f)
            c.setopt(c.NOPROGRESS, False)
            c.setopt(c.XFERINFOFUNCTION, progress)
            print('Старт загрузки ' + colored(filesApprooved[firmwarev]['file'], 'green', attrs=['bold']) + colored('...', attrs=['blink']))
            c.perform()
            print(end='\n')
            c.close()
        if hashOn != 'n':
            print('Проверяем хэш-сумму'  + colored('...', attrs=['blink']))
            BLOCKSIZE = 65536
            hasher = hashlib.md5()
            with open(filesApprooved[firmwarev]['file'], 'rb') as firmwarefile:
                buf = firmwarefile.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = firmwarefile.read(BLOCKSIZE)
            hashmd5 =  hasher.hexdigest()
            if hashmd5 != filesApprooved[firmwarev]['hash']:
                os.remove(filesApprooved[firmwarev]['file'])
                hashErr = input('Файл поврежден, повторить загрузку? ' + colored('[y]', 'green', attrs=['bold']) + '/n): ')
                hashErr = hashErr.lower()
                if hashErr == 'т':
                    hashErr = 'n'
                if hashErr == 'n':
                    errormesg('Файл поврежден', 45)
                else:
                    hashErr = True
            else:
                print(colored('Хэш сумма совпала!', 'green', attrs=['bold']))
                hashErr = False
        else: hashErr = False
    if mode == 'fastboot':
        print('Распаковываем ' + colored(filesApprooved[firmwarev]['file'], 'green', attrs = ['bold']) + colored('...', attrs = ['blink']))
        zip = zipfile.ZipFile(filesApprooved[firmwarev]['file'], 'r')
        for flashfile in flashing:
            if flashfile['file'] in zip.namelist():
                zip.extract(flashfile['file'])
            else:
                errormesg('Не обнаружены файлы для прошивки или скрипт неправильно сконфигурирован', 44)
            i += 1
        zip.close()
        os.remove(filesApprooved[firmwarev]['file'])
    elif mode == 'recovery':
        return filesApprooved[firmwarev]['file']
devparse = ppa.Suppress('devices:') + ppa.OneOrMore(ppa.Word(ppa.alphas) + ppa.Suppress("as ") + ppa.Word(ppa.alphanums + '-_ ') + ppa.Optional(ppa.Suppress(",")))
downloadUrlParse = ppa.Suppress('download config url:') + ppa.Word(ppa.alphanums + '/:-_.')
flashparse = ppa.Suppress('flash ') + ppa.OneOrMore(ppa.Word(ppa.alphanums + '-_.') + ppa.Suppress('to') + ppa.Word(ppa.alphanums + '-_') + ppa.Optional(ppa.Suppress(',')))
eraseparse = ppa.Suppress('erase ') + ppa.OneOrMore(ppa.Word(ppa.alphanums + '-_') + ppa.Optional(ppa.Suppress(',')))
#with open('config.sst', 'r') as configfile:
    #try:
        #config = configfile.readlines
    #except FileNotFoundError:
        #errormesg('Файл конфигурации не найден', 51)
directoryMode = False
try:
    with open('config.sst', 'r') as configfile:
        config = configfile.readlines()
except FileNotFoundError:
    dirmode = input('Файл конфигурации не найден, активировать DirectoryMode? (' + colored('[y]', 'green', attrs=['bold']) + '/n): ')
    if dirmode.lower() == 'n' or dirmode.lower() == 'т':
        errormesg('Файл конфигурации не найден', 51)
    else:
        directoryMode = True
if directoryMode != True:
    prod = devparse.parseString(config[0]).asList()
    config.remove(config[0])
    downloadConfigUrl = downloadUrlParse.parseString(config[0]).asList()
    downloadConfigUrl = downloadConfigUrl[0]
    config.remove(config[0])
    i = 1
    products = []
    timed = []
    print (prod)
    while i < len(prod):
        timed.append(prod.pop(i))
        i +=1
    print(timed)
    i = 0

    while i < len(timed):
        products.append({'product': prod[i],
                        'device': timed[i]})
        i += 1
cls()
print ("***********************************************************")
print ("*                    " + colored("Добро пожаловать!", "green", attrs=["bold"]) + "                    *")
print ("*             Выберите что вы хотите сделать:             *")
print ("***********************************************************")
print ("*  " + colored("1)", "green", attrs=["bold"]) + " Обновление без потери данных;                       *")
print ("*  " + colored("2)", "green", attrs=["bold"]) + " Откат (перепрошивка) с потерей данных;              *")
print ("*  " + colored("3)", "green", attrs=["bold"]) + " Откат с сохранением данных;                         *")
print ("*  " + colored("4)", "green", attrs=["bold"]) + " Обновление через recovery (sideload);               *")
print ("*  " + colored("q) Выход.", "red", attrs=["bold"]) + "                                              *")
print ("***********************************************************")
upd = str(input("Что выберем? (1/2/3/4/" + colored("[q]", "green", attrs=["bold"]) + "): "))
if upd != "1" and upd != "2" and upd != "3" and upd != '4':
    sys.exit(0)
if directoryMode != True:
    downloading = input('Загружать файлы для установки с сервера? (' + colored('[y]', 'green', attrs=['bold']) + '/n): ')
    downloading = downloading.lower()
    if downloading == 'т':
        downloading = 'n'
elif directoryMode == True:
    downloading = 'n'
if upd == "3":
    ready = None
    while ready != True:
        try:
            adbtest = subprocess.check_output(['adb', 'devices'], stderr=subprocess.STDOUT)
        except FileNotFoundError:
            errormesg('Драйвер ADB не найден', 52)
        adbtest = str(adbtest, sys.stdout.encoding)
        print(adbtest)
        if str(b'\tunauthorized\n', sys.stdout.encoding) in adbtest:
            input('Устройство не авторизовано, пожалуйста, разрешите подключение и нажмите Enter!')
        elif str(b'\trecovery\n', sys.stdout.encoding) in adbtest:
            ('Обнаружено устройство в режиме recovery, необходимо перезагрузить его в систему!')
            rs = subprocess.check_output(['adb', 'reboot'], stderr=subprocess.STDOUT)
            time.sleep(5)
            input('Включите ADB и нажмите Enter!')
        elif not str(b'\tdevice\n', sys.stdout.encoding) in adbtest:
            adbtestfail = input('Устройство не найдено, продолжить? Создание бэкапа будет пропущено!(' + colored('[y]', 'green', attrs=['bold']) + '/n): ')
            adbtestfail = adbtestfail.lower()
            if adbtestfail == 'т':
                adbtestfail == 'n'
            if adbtestfail != 'n':
                ready = True
        else:
            adbtestfail = None
            ready = True
        if adbtestfail == 'n':
            errormesg('Устройство не найдено', 11)
    if adbtestfail == None:
        print ('Разблокируйте устройство и подтвердите операцию резервного копирования!')
        adbbk = subprocess.check_output(["adb", "backup", "-all", "-nosystem", "-obb", '-apk'], stderr=subprocess.STDOUT)
try:
    adbdevice = str(subprocess.check_output(["adb", "devices"]), sys.stdout.encoding)
except FileNotFoundError:
    errormesg('Драйвер ADB не найден', 52)
if str(b'\tdevice\n', sys.stdout.encoding) in adbdevice:
    adbreboot = str(input("Обнаружено устройство, работающее по протоколу ADB. Перезагрузить его в Fastboot? (y/" + colored("[n]", "green", attrs=["bold"]) + "): "))
    if adbreboot == "Y" or adbreboot == "Н" or adbreboot == "н":
        adbreboot = "y"
    if adbreboot == "y" and upd != '4':
        try:
            subprocess.run(["adb", "reboot", "bootloader"])
        except subprocess.SubprocessError as err:
            errormesg("Устройство не обнаружено или работа с ADB не разрешена для этого ПК", 12)
        time.sleep(5)
    elif adbreboot == 'y' and upd == '4':
        try:
            subprocess.run(["adb", "reboot", "recovery"])
        except subprocess.SubprocessError as err:
            errormesg("Устройство не обнаружено или работа с ADB не разрешена для этого ПК", 12)
if upd == '4':
    if downloading != 'n':
        i = 0
        for product in products:
            i += 1
            print(colored(str(i) + ') ', 'green', attrs=['bold']) + product['device'] + ';')
        sideloadDevice = input('Выберите устройство (' + colored('[1]', 'green', attrs = ['bold']) + '): ')
        if sideloadDevice == '':
            sideloadDevice = 0
        else:
            sideloadDevice = int(sideloadDevice) - 1
        sideloadFile = downloader('recovery', products[sideloadDevice]['product'].lower())
        #sideloadFile = filesApprooved[firmwarev]['file']
    else:
        i = 0
        sideloadList = []
        for file in os.listdir(os.path.dirname(os.path.realpath(__file__))):
            if file.endswith('.zip'):
                i += 1
                print (colored(str(i) + ')', 'green', attrs['bold']) + ' ' + file + ';')
                sideloadList.append(file)
        firmwarev = input('Какой файл прошивать? (' + colored('[1]', 'green', attrs=['bold']) + '): ')
        if firmwarev == '':
            firmwarev = 0
        else:
            firmwarev = int(firmwarev) - 1
        sideloadFile = sideloadList[firmwarev]
    input('Активируйте Sideload и нажмите Enter')
    adbdevice = str(subprocess.check_output(["adb", "devices"]), sys.stdout.encoding)
    if not str(b'\tsideload\n', sys.stdout.encoding) in adbdevice:
        errormesg('Устройство не обнаружено', 12)
    print('Отправляем ' + sideloadFile + colored('...', attrs = ['blink']))
    sideload = subprocess.check_output(['adb', 'sideload', sideloadFile], stderr=subprocess.STDOUT)
    adbreboot = input('Перезагрузить устройство? (y/' + colored('[n]', 'green', attrs=['bold']) + '): ')
    print('Отправлено успешно!')
    if adbreboot == 'Y' or adbreboot == 'Н' or adbreboot == 'н':
        adbreboot == 'y'
    if adbreboot == 'y':
        subprocess.run(['adb', 'reboot'], stderr=subprocess.STDOUT)
    sys.exit(0)
sudoer = None
try:
    fbtdev = subprocess.check_output(["fastboot", "getvar", "product"], stderr=subprocess.STDOUT, timeout=1)
except FileNotFoundError:
    ('Драйвер Fastboot не найден', 52)
except subprocess.TimeoutExpired as err:
    if sys.platform == 'linux' or sys.platform == 'linux2' or sys.platform == 'darvin':
        sudoer = str(input('Недостаточно прав для работы с Fastboot, использовать ' + colored('sudo', 'green', attrs=['bold']) + '? (' + colored('[y]', 'green', attrs=['bold']) + '/n): '))
    elif sys.platform == 'win32':
        errormesg('Устройство не обнаружено или недостаточно прав для работы с Fastboot', 21)
    else:
        errormesg('Недостаточно прав для работы с Fastboot', 21)
except subprocess.CalledProcessError as err:
    errormesg('Обнаружена проблема в работе Fastboot, требуется проверка с Вашей стороны', 2000 + err.returncode)
if sudoer == 'N' or sudoer == 'т' or sudoer == 'Т' or sudoer == 'n':
    sudoer = False
else:
    sudoer == True
if sudoer != None:
    if sudoer != False:
        print ('Возможно сейчас вас попросят ввести пароль!')
        print (colored('Если вы "застряли" на этом месте проверьте подключение устройства!', 'red', attrs=['bold']))
        if sys.platform == 'linux' or sys.platform == 'darvin':
            try:
                fbtdev = subprocess.check_output(["sudo", "fastboot", "getvar", "product"], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as err:
                errormesg('Обнаружена проблема в работе Fastboot, требуется проверка с Вашей стороны', 2000 + err.returncode)
        if sys.platform == 'win32':
            errormesg('Недостаточно прав для работы с Fastboot, запустите скрипт от имени администратора', 21)
    else:
        errormesg('Недостаточно прав для работы с Fastboot', 21)
flashrec = input('Прошивать recovery? ' + colored('Этот пункт не спасет если у вас установлен флаг "Обновлять режим восстановления!" ', 'red', attrs=['bold']) + '(y/' + colored('[n]', 'green', attrs=['bold']) + '): ')
if flashrec == 'Y' or flashrec == 'Н' or flashrec == 'н':
    flashrec = 'y'
flashing = []
i = 0
if directoryMode == False:
    fbtdev = str(fbtdev, sys.stdout.encoding)
    devparse = ppa.ZeroOrMore(ppa.Suppress('product: ') + ppa.Word(ppa.alphas))
    devices = devparse.parseString(fbtdev).asList()
    whatican = []
    while i < len(products):
        if products[i]['product'] in devices:
            whatican.append({'product': products[i]['product'],
                            'device': products[i]['device']})
        i += 1
    i = 0
    if len(whatican) > 1:
        print('Подключено несколько устройств,' + ' выберите необходимое из списка ниже:')
        i = 0
        for device in whatican:
            i += 1
            print (colored(str(i) + ') ', 'green', attrs=['bold']) + device['device']) + ';'
        devnum = input('Введите номер [1]: ')
        if devnum == '':
            devnum = 0
        else:
            devnum = int(devnum) - 1
    elif len(whatican) == 0:
        errormesg('Поддерживаемые устройства не обнаружены', 22)
    else:
        devnum = 0;
    devtest = input('Выбрано устройство ' + colored(whatican[devnum]['device'], 'green', attrs=['bold']) + ', продолжить? (' + colored('[y]', 'green', attrs=['bold']) + '/n): ')
    if devtest == 'N' or devtest == 'т' or devtest == 'Т':
        devtest = 'n'
    if devtest == 'n':
        errormesg('Устройство выбрано неверно, выполнение остановлено пользователем', 31)
    i = 0
    test = 0
    while i < len(config):
        if whatican[devnum]['product'].lower() in config[i].lower():
            flashfiles = flashparse.parseString(config[i+1]).asList()
            if not 'none' in config[i+2]:
                eraseparts = eraseparse.parseString(config[i+2]).asList()
            else:
                eraseparts = None
        i+=3
    i = 0
    while i < len(flashfiles):
        flashing.append({'file': flashfiles[i],
                        'part': flashfiles[i+1]})
        i+=2
elif directoryMode == True:
    eraseparts = None
    parseFiles = (ppa.Word(ppa.alphanums + '-_'))('part') + ppa.Suppress('.' + ppa.Word(ppa.alphas))
    for file in os.listdir(os.path.dirname(os.path.realpath(__file__))):
        if file.endswith('.mbn') or file.endswith('.img') or file.endswith('.bin'):
            part = parseFiles.parseString(file).part
            for changes in extraParts:
                if part == changes['in']:
                    part = changes['out']
            if file != data['file'] and file != recovery['file']:
                flashing.append({'file': file,
                                'part': part})
if flashrec == 'y' and not 'recovery' in flashing:
    #Just name of recovery file, almost always it's named recovery.img
    flashing.append({'file': 'recovery.img',
                     'part': 'recovery'})
if upd != '1'and not 'userdata' in flashing:
    #Same as recovery
    flashing.append({'file': 'userdata.img',
                     'part': 'userdata'})
if downloading != 'n':
    downloader('fastboot', whatican[devnum]['product'].lower())
for files in flashing:
    if not files['file'] in os.listdir(os.path.dirname(os.path.realpath(__file__))):
        filenotfound = input('Файл ' + colored(files['file'], 'green', attrs=['bold']) + ' не найден в папке со скриптом, продолжить? (y/' + colored('[n]', 'green', attrs=['bold']) + '): ')
        if filenotfound == 'Y' or filenotfound == 'н' or filenotfound == 'Н':
            filenotfound = 'y'
        if filenotfound != 'y':
            errormesg('Файл ' + files['file'] + ' не найден в папке со скриптом', 53)
if sudoer != None and sudoer != False:
    if sys.platform == 'linux' or sys.platworm == 'darvin':
        asadmin = 'sudo'
    else:
        asadmin = ''
if eraseparts != None:
    for erasepart in eraseparts:
        if sys.platform == 'linux' or sys.platform == 'darwin':
            with subprocess.Popen([asadmin, 'fastboot', 'erase', erasepart], stderr=subprocess.PIPE) as erasepipe:
                try:
                    erasepipe
                    for line in iter(erasepipe.stderr.readline, b''):
                        eraseinfo = str(line.rstrip(), sys.stdout.encoding)
                        if 'erasing' in eraseinfo:
                            print ('Очищаем ' + colored(erasepart, 'green', attrs=['bold']) + '...')
                        if 'OKAY' in eraseinfo:
                            print (colored('Успешно!', 'green', attrs=['bold', 'blink']))
                except subprocess.CalledProcessError as err:
                    if err.returncode == 13:
                        print ('Недостаточно прав для работы с Fastboot', 21)
                    else:
                        print ('Во время очистки раздела произошла ошибка, пожалуйста, попробуйте снова  ', 20 + err.returncode)
        else:
            with subprocess.Popen(['fastboot', 'erase', erasepart], stderr=subprocess.PIPE) as erasepipe:
                try:
                    erasepipe
                    for line in iter(erasepipe.stderr.readline, b''):
                        eraseinfo = str(line.rstrip(), sys.stdout.encoding)
                        if 'erasing' in eraseinfo:
                            print ('Очищаем ' + colored(erasepart, 'green', attrs=['bold']) + '...')
                        if 'OKAY' in eraseinfo:
                            print (colored('Успешно!', 'green', attrs=['bold', 'blink']))
                        #print(colored('>>> ', 'green', attrs=['blink', 'bold']) + eraseinfo)
                except subprocess.CalledProcessError as err:
                    if err.returncode == 13:
                        print ('Недостаточно прав для работы с Fastboot', 21)
                    else:
                        print ('Во время очистки раздела произошла ошибка, пожалуйста, попробуйте снова  ', 20 + err.returncode)
for flashlist in flashing:
    if sys.platform == 'linux' or sys.platform == 'darwin':
        with subprocess.Popen([asadmin, 'fastboot', 'flash', flashlist['part'], flashlist['file']], stderr=subprocess.PIPE) as flashpipe:
            try:
                flashpipe
                infoparse = ppa.Suppress("sending sparse '" + flashlist['part'] + "'") + ppa.Word(ppa.nums + '/')
                for line in iter(flashpipe.stderr.readline, b''):
                    flashinfo = str(line.rstrip(), sys.stdout.encoding)
                    if 'erasing' in flashinfo:
                        print ('Очищаем ' + colored(flashlist['part'], 'green', attrs=['bold']) + '...')
                    if 'sending' in flashinfo and '/' in flashinfo:
                        sparsenum = infoparse.parseString(flashinfo).asList()
                        print ('Отправляем ' + colored(flashlist['part'] + ' ' + str(sparsenum[0]), 'green', attrs=['bold']) + '...')
                    elif 'sending' in flashinfo:
                        print ('Отправляем ' + colored(flashlist['part'], 'green', attrs=['bold']) + '...')
                    if 'writing' in flashinfo:
                        print ('Прошиваем ' + colored(flashlist['part'], 'green', attrs=['bold']) + '...')
                    if 'OKAY' in flashinfo:
                        print (colored('Успешно!', 'green', attrs=['bold', 'blink']))
                    if "partition table doesn't exist" in flashinfo:
                        print (colored('Скрипт настроен неправильно, раздел не прошит!', 'red', attrs=['bold', 'blink']))
                    if 'remote: device is locked. Cannot erase' in flashinfo or 'remote: device is locked. Cannot flash' in flashinfo:
                        print (colored('Устройство заблокировано, не удалось завершить операцию!', 'red', attrs=['bold', 'blink']))
            except subprocess.CalledProcessError as err:
                if err.returncode == 13:
                    print ('Недостаточно прав для работы с Fastboot', 21)
                else:
                    print ('Во время прошивки раздела произошла ошибка, пожалуйста, попробуйте снова  ', 20 + err.returncode)
    else:
        with subprocess.Popen(['fastboot', 'flash', flashlist['part'], flashlist['file']], stderr=subprocess.PIPE) as flashpipe:
            try:
                flashpipe
                for line in iter(flashpipe.stderr.readline, b''):
                    flashinfo = str(line.rstrip(), sys.stdout.encoding)
                    if 'erasing' in flashinfo:
                        print ('Очищаем ' + colored(flashlist['part'], 'green', attrs=['bold']) + '...')
                    if 'sending' in flashinfo and '/' in flashinfo:
                        sparsenum = infoparse.parseString(flashinfo).asList()
                        print ('Отправляем ' + colored(flashlist['part'] + ' ' + str(sparsenum[0]), 'green', attrs=['bold']) + '...')
                    elif 'sending' in flashinfo:
                        print ('Отправляем ' + colored(flashlist['part'], 'green', attrs=['bold']) + '...')
                    if 'writing' in flashinfo:
                        print ('Прошиваем ' + colored(flashlist['part'], 'green', attrs=['bold']) + '...')
                    if 'OKAY' in flashinfo:
                        print (colored('Успешно!', 'green', attrs=['bold', 'blink']))
                    if "partition table doesn't exist" in flashinfo:
                        print (colored('Скрипт настроен неправильно, раздел не прошит!', 'red', attrs=['bold', 'blink']))
                    if 'remote: device is locked. Cannot erase' in flashinfo or 'remote: device is locked. Cannot flash' in flashinfo:
                        print (colored('Устройство заблокировано, не удалось завершить операцию!', 'red', attrs=['bold', 'blink']))
                    #print(colored('>>> ', 'green', attrs=['blink', 'bold']) + flashinfo)
            except subprocess.CalledProcessError as err:
                if err.returncode == 13:
                    print ('Недостаточно прав для работы с Fastboot', 21)
                else:
                    print ('Во время прошивки раздела произошла ошибка, пожалуйста, попробуйте снова  ', 20 + err.returncode)
fbreboot = input('Перезагрузить устройство? (y/' + colored('[n]', 'green', attrs=['bold']) + '): ')
if fbreboot == 'Y' or fbreboot == 'Н' or fbreboot == 'н':
    fbreboot == 'y'
fbrebooterr = ''
if fbreboot == 'y' or upd == '3':
    try:
        subprocess.check_output([asadmin, 'fastboot', 'reboot'], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        fbrebooterr = input('Подключение ' + colored('не удалось', 'red', attrs=['bold']) + ', продолжить? (y/' + colored('[n]', 'green', attrs=['bold']) + '): ')
        if fbrebooterr == 'Y' or fbrebooterr == 'Н' or fbrebooterr == 'н':
            fbrebooterr = 'y'
        if fbrebooterr != 'y':
            errmesg('Не удалось перезагрузить устройство', 'Fastboot ' + err.returncode)
if fbrebooterr == 'y' and upd == '3':
    input('Пожалуйста, перезагрузите устройство вручную, включите отладку и нажмите Enter')
elif fbrebooterr == '' and upd == '3':
    input('Пожалуйста, когда устройство перезагрузится включите отладку и нажмите Enter')
if upd == '3':
    success = None
    rstrestore = None
    print('Подтвердите восстановление на устройстве!')
    while success != True:
        try:
            subprocess.check_output(['adb', 'restore', 'backup.ab'], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            rstrestore = input('Восстановление было прервано, повторить? (' + colored('[y]', 'green', attrs=['bold']) + '/n): ')
            if rstrestore == 'N' or rstrestore == 'Т' or rstrestore == 'т':
                rstrestore = 'n'
            if rstrestore != 'n':
                success = False
            else:
                errormesg('Восстановление было прервано', 13)
        else:
            success = True
    input(colored('Успешно! ', 'green', attrs=['bold', 'blink']) + 'Нажмите Enter чтобы закончить.')
    cls()
    sys.exit(0)
