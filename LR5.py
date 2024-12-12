import re
import os
import sqlite3
import tkinter as tk
from tkinter import messagebox
import uuid
import bcrypt
import random
import string
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import ctypes
from datetime import datetime

if not os.path.exists('key.key'):
    encryption_key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(encryption_key)
else:
    with open('key.key', 'rb') as key_file:
        encryption_key = key_file.read()

# Создание экземпляра шифровальщика
cipher = Fernet(encryption_key)

# Подключаемся к базе данных
connection = sqlite3.connect('user.db')
curs = connection.cursor()

# Создаем таблицы
curs.execute('''CREATE TABLE IF NOT EXISTS user (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    login VARCHAR(50) NOT NULL UNIQUE CHECK(length(login) = 4 AND login GLOB '[0-9][0-9][0-9][0-9]'),
    password VARCHAR(100) NOT NULL,
    email VARCHAR(50) NOT NULL,
    phone VARCHAR(10) NOT NULL,
    fio VARCHAR(50) NOT NULL,
    address VARCHAR(30) NOT NULL        
)''')

connection.commit()

curs.execute('''CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) NOT NULL UNIQUE,
    access_level INTEGER DEFAULT 1 CHECK(access_level BETWEEN 1 AND 3),
    content_hash TEXT
);''')


flag = 0
connection.commit()
# Получение текущей директории через os.path... не работают при сборке exe файла. Возможно починю
files_dir = 'D:/projects/уник/5v2'

def hide_file(file_path):
    # Константа для скрытого файла
    FILE_ATTRIBUTE_HIDDEN = 0x02
    # Устанавливаем атрибут файла
    ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN)

# Функции для получения UUID и его проверки
def get_uuid():
    global pc_uuid
    try:
        pc_uuid = uuid.getnode()
        #print(pc_uuid)
        return pc_uuid
    except Exception as e:
        print(f"Error retrieving UUID: {e}")
        return False

def check_uuid():
    global pc_uuid
    if get_uuid() == 84585006017818:
        return True
    else:
        return False

# Проверка пароля и логина
def check_password(password):
    return (len(password) == 6 and re.search(r'[a-zA-Z]', password) and re.search(r'\d', password))

def check_hashed_password(password, hashed_password):
    #messagebox.showinfo("", F'{hashed_password}')
    if isinstance(hashed_password, str):
        hashed_password_bytes = hashed_password.encode('utf-8')
    else:
        hashed_password_bytes = hashed_password

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password_bytes):
        return True
    else:
        #messagebox.showerror('', 'Пароль не совпал с хешированным')
        return False

def check_login(login):
    return (len(login) == 4 and login.isdigit())

def captcha():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for i in range(5))

def captcha_check(captcha_ins, captcha_get):
    if captcha_ins != captcha_get:
        messagebox.showerror('', 'Каптча не совпадает. Попробуйте ещё раз.')
        return
    else:
        messagebox.showinfo('', 'Каптча введена верно.')
        return True

def check_status(status):
    if status == 'busy':
        return False
    else:
        return True
    
def swap_status(filename):
    # Извлекаем текущий статус файла
    curs.execute('SELECT status FROM files WHERE name = ?', (filename,))
    tmp = curs.fetchone()
    
    # Проверяем статус
    if tmp and tmp[0] == 'busy':
        curs.execute('UPDATE files SET status = "enable" WHERE name = ?', (filename,))
    else:
        curs.execute('UPDATE files SET status = "busy" WHERE name = ?', (filename,))
    
    # Сохраняем изменения в базе данных
    connection.commit()
    return True

    
# Обработка входа пользователя
def login():
    global user_login
    login = login_prog_log.get()
    password = password_prog_log.get()
    global counter_wrong_logins

    if not check_login(login):
        messagebox.showerror('', 'Логин должен состоять из 4-ех цифр')
        counter_wrong_logins += 1
        if counter_wrong_logins == 3:
            counter_wrong_logins = 0
            captchaw()
        return
    
    curs.execute("SELECT * FROM user WHERE login=?", (login, ))
    tmp = curs.fetchone()

    if tmp is None:
        messagebox.showerror('', 'Неправильный логин или пароль')
        counter_wrong_logins += 1
        if counter_wrong_logins == 3:
            counter_wrong_logins = 0
            captchaw()
            
        return

    probably_password = tmp[2]

    if check_hashed_password(password, probably_password):
        user_login = login
        working_processw()  
        counter_wrong_logins = 0
    else:
        messagebox.showerror('', 'Неправильный логин или пароль')
        counter_wrong_logins += 1
        if counter_wrong_logins == 3:
            counter_wrong_logins = 0
            captchaw()


def registration():
    login = login_prog.get()
    password = password_prog.get()
    email = email_prog.get()
    phone = phone_prog.get()
    fio = fio_prog.get()
    address = address_prog.get()

    if not check_login(login):
        messagebox.showerror('', 'Логин должен состоять из 4-ех цифр')
        return
    
    if not check_password(password):
        messagebox.showerror('', 'Пароль должен состоять из 6 символов и содержать как цифры, так и буквы')
        return
    
    if not (login and password and email != 'Email' and phone != 'Телефон' and fio != 'ФИО' and address != 'Адрес'):
        messagebox.showerror('', 'Вы забыли заполнить поле')
        return 

    try:
        # Проверяем, есть ли пользователь с таким же логином
        curs.execute("SELECT login FROM user WHERE login = ?", (login,))
        if curs.fetchone() is not None:
            messagebox.showerror('', 'Пользователь с таким логином уже существует')
            return
        
        curs.execute("INSERT INTO user (login, password, email, phone, fio, address) VALUES (?, ?, ?, ?, ?, ?)", 
                     (login, hash_password(password), email, phone, fio, address))
        connection.commit()
        messagebox.showinfo('', 'Успешно')
        loginw()

    except Exception:
        messagebox.showerror('', 'Ошибка при регистрации. Возможно, пользователь с таким логином уже существует.')

# Основное окно
root = tk.Tk()
root.title("Система входа и регистрации")
root.geometry("400x600") 
for file_name in os.listdir(files_dir):
    if file_name.endswith('.txt'):  # Проверяем расширение файла
        full_path = os.path.join(files_dir, file_name)
        print(full_path)
        hide_file(full_path)  # Делаем файл скрытым
        print(f"Файл {file_name} скрыт.")


# Глобальные переменные для хранения полей ввода
login_prog = None
password_prog = None
email_prog = None
phone_prog = None
fio_prog = None
address_prog = None
flag = False
counter_wrong_logins = 0
counter = 0
login_prog_log = None
pass_level = 0
password_prog_log = None
captcha_insert = ''
captcha_gen = ''
check_filename = ''

# Функция шифрования
def encrypt_content(content):
    return cipher.encrypt(content.encode('utf-8'))

# Функция расшифровки

def decrypt_content(encrypted_content):
    cipher = Fernet(encryption_key)
    decrypted_bytes = cipher.decrypt(encrypted_content)
    return decrypted_bytes.decode('utf-8')


# Функция вычисления хеша
def calculate_hash(content):
    # Проверяем тип входных данных и декодируем их, если это bytes
    if isinstance(content, bytes):
        content = content.decode('utf-8')  # Преобразуем в строку
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


# Функция для установки начального текста в поле и его удаления при нажатии на него
def set_placeholder(entry, placeholder_text):
    entry.insert(0, placeholder_text)
    entry.config(fg='grey')
    
    # Функция очистки текста при нажатии на него
    def on_focus_in(event):
        if entry.get() == placeholder_text:
            entry.delete(0, tk.END)
            entry.config(fg='black')
    
    # Функция возврата текста, если поле пустое
    def on_focus_out(event):
        if entry.get() == '':
            entry.insert(0, placeholder_text)
            entry.config(fg='grey')
    
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)

# Функция для изменения шрифта и размера кнопок
def configure_widgets(widget):
    widget.config(font=("Arial", 14))
    return widget

# Выбор действия
def login_or_registration():
    global counter
    global flag
    counter = 0
    if flag == False:
        if check_uuid(): 
            True
            flag = True
        else:
            messagebox.showerror('', 'Вход невозможен. Ошибка UUID')
   

    for widget in root.winfo_children():
        widget.destroy()


    configure_widgets(tk.Button(root, text="Вход", command=loginw)).pack(pady=20)
    configure_widgets(tk.Button(root, text="Регистрация", command=registrationw)).pack(pady=20)


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


def registrationw():
    global login_prog, password_prog, email_prog, phone_prog, fio_prog, address_prog

    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Регистрация", font=("Arial", 24)).pack(pady=20)

    login_prog = tk.Entry(root)
    configure_widgets(login_prog).pack(pady=10)
    set_placeholder(login_prog, "Логин (4 цифры)")

    password_prog = tk.Entry(root)
    configure_widgets(password_prog).pack(pady=10)
    set_placeholder(password_prog, "6 символов(цифры и буквы)")

    email_prog = tk.Entry(root)
    configure_widgets(email_prog).pack(pady=10)
    set_placeholder(email_prog, "Email")

    phone_prog = tk.Entry(root)
    configure_widgets(phone_prog).pack(pady=10)
    set_placeholder(phone_prog, "Телефон")

    fio_prog = tk.Entry(root)
    configure_widgets(fio_prog).pack(pady=10)
    set_placeholder(fio_prog, "ФИО")

    address_prog = tk.Entry(root)
    configure_widgets(address_prog).pack(pady=10)
    set_placeholder(address_prog, "Адрес")

    configure_widgets(tk.Button(root, text="Зарегистрироваться", command=registration)).pack(pady=20)
    configure_widgets(tk.Button(root, text="Назад", command=login_or_registration)).pack(pady=10)


def loginw():
    global login_prog_log, password_prog_log

    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Вход", font=("Arial", 24)).pack(pady=20)

    login_prog_log = tk.Entry(root)
    configure_widgets(login_prog_log).pack(pady=10)
    set_placeholder(login_prog_log, "Логин (4 цифры)")

    password_prog_log = tk.Entry(root, show="*")
    configure_widgets(password_prog_log).pack(pady=10)
    set_placeholder(password_prog_log, "Пароль")

    configure_widgets(tk.Button(root, text="Войти", command=login)).pack(pady=20)
    configure_widgets(tk.Button(root, text="Назад", command=login_or_registration)).pack(pady=10)


def captchaw():
    global captcha_insert, captcha_gen
    captcha_gen = captcha()
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text=captcha_gen, font=("Arial", 24)).pack(pady=20)

    captcha_insert = tk.Entry(root)
    configure_widgets(captcha_insert).pack(pady=30)

    configure_widgets(tk.Button(root, text="Проверить", command=lambda : loginw() if captcha_check(captcha_gen, captcha_insert.get()) else captchaw())).pack(pady=40)




def verify_file_content(file_path, expected_hash):
    try:
        with open(file_path, 'rb') as file:
            encrypted_content = file.read()
            #print(f"Считанное содержимое (зашифрованное): {encrypted_content}")
            decrypted_content = decrypt_content(encrypted_content)
            #print(f"Расшифрованное содержимое: {decrypted_content}")
    except InvalidToken as e:
        print(f"Ошибка расшифровки: {e}")
        messagebox.showerror('', 'файл поврежден или ключ неверный')
        return False

    calculated_hash = calculate_hash(decrypted_content)  # Считаем хеш расшифрованного содержимого

    if calculated_hash == expected_hash:
        return True
    else:
        return False

def working_processw():
    global login_prog_log
    global counter
    global pass_level 
    global check_filename

    if counter == 0:
        login = login_prog_log.get()
        curs.execute('SELECT pass_level FROM user WHERE login = ?', (login, ))
        pass_level = curs.fetchone()[0]
        counter += 1

    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text='Доступные файлы', font=('Arial', 24)).pack(pady=10)

    # Выбираем только файлы, доступные для текущего уровня доступа
    curs.execute("SELECT name FROM files WHERE access_level <= ?", (pass_level,))
    file_list = [row[0] for row in curs.fetchall()]

    for file_name in file_list:
        file_button = tk.Button(root, text=file_name[:-4], command=lambda f=file_name: working_process(f, pass_level))
        configure_widgets(file_button).pack(pady=5)

    if pass_level >= 2:
        tk.Button(root, text='Создать новый файл', font=('Arial', 18), command=create_new_file).pack(pady=20)

    if pass_level == 3:
        tk.Button(root, text='Изменить уровень доступа пользователей', font=('Arial', 18), command=change_user_access).pack(pady=10)
        tk.Button(root, text='Изменить уровень доступа файлов', font=('Arial', 18), command=change_file_access).pack(pady=10)
    
    tk.Button(root, text='Назад', font=('Arial', 18), command=login_or_registration).pack(pady=10)

def working_process(file_name, pass_level):
    global check_filename
    global user_login
    
    # Проверяем статус файла
    curs.execute('SELECT status FROM files WHERE name = ?', (file_name,))
    tt = curs.fetchone()
    
    # Если файл не найден в базе данных
    if not tt:
        messagebox.showerror('', 'Ошибка: файл не найден в базе данных!')
        working_processw()
        return
    
    # Проверка статуса
    if check_status(tt[0]):
        check_filename = file_name
        swap_status(check_filename)
        for widget in root.winfo_children():
            widget.destroy()

        tk.Label(root, text=f'Файл: {file_name[:-4]}', font=('Arial', 18)).pack(pady=10)

        file_path = os.path.join(files_dir, file_name)

        # Извлекаем хеш из базы данных
        curs.execute("SELECT content_hash FROM files WHERE name = ?", (file_name,))
        expected_hash = curs.fetchone()
        if expected_hash is None:
            messagebox.showerror('', 'Ошибка: файл не найден в базе данных!')
            working_processw()
            return

        expected_hash = expected_hash[0]

        if not verify_file_content(file_path, expected_hash):
            #messagebox.showerror('', 'Ошибка: содержимое файла изменено и не совпадает с базой данных!')
            working_processw()
            return

        with open(file_path, 'rb') as file:
            encrypted_content = file.read()
            content = decrypt_content(encrypted_content)

        text_widget = tk.Text(root, wrap='word', height=15, width=40)
        text_widget.insert('1.0', content)
        text_widget.config(state="disabled" if pass_level < 2 else "normal")  # Только чтение для уровня 1
        text_widget.pack(pady=10)

        if pass_level >= 2:
            def save_changes():
                global user_login
                FILE_ATTRIBUTE_HIDDEN = 0x02
                FILE_ATTRIBUTE_NORMAL = 0x80
                new_content = text_widget.get('1.0', tk.END).strip()
                new_encrypted_content = encrypt_content(new_content)
                new_content_hash = calculate_hash(new_content)
                current_time = datetime.now()
                formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
                ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_NORMAL)

                # Записываем данные в файл
                with open(file_path, 'wb') as file:
                    file.write(new_encrypted_content)

                ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_HIDDEN)

                curs.execute("UPDATE files SET content_hash = ? WHERE name = ?", (new_content_hash, file_name, ))
                curs.execute('SELECT id FROM files WHERE name = ?', (file_name,))

                #print(user_login)
                tmp = curs.fetchone()[0]
                curs.execute('''INSERT INTO filechangehistory(file_id, file_name, user_login, last_save_time)
                VALUES (?, ?, ?, ?)''', (tmp, file_name, user_login, formatted_time))

                connection.commit()
                messagebox.showinfo('', 'Изменения сохранены')

            tk.Button(root, text='Сохранить изменения', font=('Arial', 18), command=save_changes).pack(pady=10)
    
        def to_wpr():
            swap_status(check_filename)
            working_processw()
            return
        
        tk.Button(root, text='Назад к списку файлов', font=('Arial', 18), command=to_wpr).pack(pady=10)
    else:
        messagebox.showerror('', 'Файл уже открыт')
        working_processw()
        return

def create_new_file():
    global pass_level, file_name_entry, access_level_entry, text_widget

    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text='Создать новый файл', font=('Arial', 18)).pack(pady=10)
    file_name_entry = tk.Entry(root)
    configure_widgets(file_name_entry).pack(pady=10)
    set_placeholder(file_name_entry, 'Имя нового файла')

    access_level_entry = tk.Entry(root)
    configure_widgets(access_level_entry).pack(pady=10)
    set_placeholder(access_level_entry, 'Уровень доступа (1-3)')

    text_widget = tk.Text(root, wrap='word', height=15, width=40)
    text_widget.pack(pady=10)

    tk.Button(root, text='Сохранить файл', command=save_new_file, font=('Arial', 18)).pack(pady=10)

def save_new_file():
    global file_name_entry, access_level_entry, text_widget

    # Получаем значения из полей
    file_name = file_name_entry.get().strip()
    access_level = access_level_entry.get().strip()
    file_content = text_widget.get("1.0", tk.END).strip()

    # Проверка корректности данных
    if not file_name or not access_level:
        messagebox.showerror("", "Введите имя файла и уровень доступа!")
        return

    if not access_level.isdigit() or not (1 <= int(access_level) <= 3):
        messagebox.showerror("", "Уровень доступа должен быть числом от 1 до 3!")
        return

    # Добавляем расширение .txt, если его нет
    if not file_name.endswith('.txt'):
        file_name += '.txt'

    # Сохраняем файл
    try:
        encrypted_content = encrypt_content(file_content)  # Шифруем содержимое
        file_path = os.path.join(files_dir, file_name)
        with open(file_path, 'wb') as file:
            file.write(encrypted_content)

        # Вычисляем хеш содержимого и сохраняем его в базе данных
        content_hash = calculate_hash(file_content)
        curs.execute("INSERT INTO files (name, access_level, content_hash) VALUES (?, ?, ?)", 
                     (file_name, int(access_level), content_hash))
        connection.commit()

        messagebox.showinfo("", f"Файл '{file_name}' сохранён!")

    except sqlite3.IntegrityError:
        messagebox.showerror("", f"Файл с именем '{file_name}' уже существует!")
    except Exception as e:
        messagebox.showerror("", f"Не удалось сохранить файл: {e}")
        return

    # Очищаем текстовое поле после сохранения
    text_widget.delete("1.0", tk.END)

    # Интерфейс после сохранения
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text=f"Файл '{file_name}' успешно сохранён.", font=('Arial', 14)).pack(pady=10)

    # Кнопка для сохранения нового файла
    tk.Button(root, text='Создать новый файл', font=('Arial', 18), command=create_new_file).pack(pady=10)

    # Кнопка для возврата в меню работы с файлами
    tk.Button(root, text='Назад', font=('Arial', 18), command=working_processw).pack(pady=10)



def change_user_access():
    global pass_level

    if pass_level < 3:
        messagebox.showwarning('', 'У вас нет прав для изменения уровней доступа.')
        working_processw()
        return

    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text='Изменить уровень доступа', font=('Arial', 18)).pack(pady=10)
    user_login_entry = tk.Entry(root)
    configure_widgets(user_login_entry).pack(pady=10)
    set_placeholder(user_login_entry, 'Логин пользователя')

    new_level_entry = tk.Entry(root)
    configure_widgets(new_level_entry).pack(pady=10)
    set_placeholder(new_level_entry, 'Новый уровень доступа (1-3)')

    def update_access_level():
        target_login = user_login_entry.get()
        try:
            new_level = int(new_level_entry.get())
            if new_level not in [1, 2, 3]:
                raise ValueError('Уровень должен быть от 1 до 3.')
            
            curs.execute('UPDATE user SET pass_level = ? WHERE login = ?', (new_level, target_login))
            connection.commit()
            messagebox.showinfo('', f'Уровень доступа пользователя {target_login} обновлен до {new_level}')
            working_processw()

        except ValueError as e:
            messagebox.showerror('', f'Ошибка: вы забыли заполнить поле')

    tk.Button(root, text='Обновить уровень доступа', font=('Arial', 18), command=update_access_level).pack(pady=10)
    tk.Button(root, text='Назад к списку файлов', font=('Arial', 18), command=working_processw).pack(pady=10)

def change_file_access():
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text='Изменить уровень доступа к файлу', font=('Arial', 18)).pack(pady=10)

    file_name_entry = tk.Entry(root)
    configure_widgets(file_name_entry).pack(pady=10)
    set_placeholder(file_name_entry, 'Имя файла')

    new_level_entry = tk.Entry(root)
    configure_widgets(new_level_entry).pack(pady=10)
    set_placeholder(new_level_entry, 'Новый уровень доступа (1-3)')

    def update_file_access_level():
        file_name = file_name_entry.get()
        try:
            new_level = int(new_level_entry.get())
            if new_level not in [1, 2, 3]:
                raise ValueError('Уровень должен быть от 1 до 3.')
            
            curs.execute('UPDATE files SET access_level = ? WHERE name = ?', (new_level, file_name))
            connection.commit()
            messagebox.showinfo('', f'Уровень доступа файла {file_name} обновлен до {new_level}')
            working_processw()

        except ValueError:
            messagebox.showerror('', 'Ошибка: уровень доступа должен быть числом от 1 до 3.')
        except sqlite3.IntegrityError:
            messagebox.showerror('', f'Файл {file_name} не найден.')

    tk.Button(root, text='Обновить уровень доступа', font=('Arial', 18), command=update_file_access_level).pack(pady=10)
    tk.Button(root, text='Назад к списку файлов', font=('Arial', 18), command=working_processw).pack(pady=10)

login_or_registration()
root.mainloop()


connection.close()
