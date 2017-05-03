# fastboot_Flasher_py
На данный момент скрипт умеет:
  1. Прошивать устройства через fastboot согласно конфигурационного файла config.sst;
  2. Прошивать устройства через sideload, на данный момент работает только со скачанными через скрипт файлами, либо с файлом 'sideload.zip'
  3. Скачивать прошивки с сервера, url файла-базы прошивок указывается в файле config.sst;
  4. Проверять MD5 суммы скачанных архивов;
  5. Откатывать версию Android с сохранением пользовательского софта и его данных;
# Настройка скрипта:
config.sst:
1. строка:company - < Имя компании >
    Используется для указания производителя устройств, при необходимости.
  2. строка: devices: < Кодовое имя устройства > as < Красивое имя для пользователя >
    Перечисление поддерживаемых устройств через запятую.
  3. строка: download config url: < URL файла с информацией для загрузчика прошивок >
    Указывается ссылка на файл с информацией о прошивках, по этой ссылке так же будет проводиться проверка доступности сервера.
  4. строка: < Кодовое имя устройства >
    Начинает секцию устройства, в сроке можно перечислять несколько устройств, если конфигаруция скрипта совпадает. Не чувствительно к регистру.
  5. строка: flash < Файл > to < Раздел >
    Указывает какой файл куда прошивать, файлы обязательно должны находиться в скачиваемых архивах, иначе выполнение будет остановлено. Перечисление пар Файл to Раздел через запятую.
  6. строка: erase < Раздел >
    Указывает какие разделы необходимо очистить перед прошивкой, none если таких разделов нет.
  строки с 4 по 6 повторяются для каждого поддерживаемого устройства.

download.txt - cодержит строки вида < Кодовое имя устройства > < Имя файла > < MD5 > < Ссылка на файл >
  1. Кодовое имя устройства не чувствительно к регистру;
  2. Имя файла должно содержать метод прошивки (fastboot, recovery), на данный момент тестировались только zip-архивы;
  3. MD5, no comments;
  4. Прямая ссылка на файл.
