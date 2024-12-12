import sqlite3

# Подключение к SQLite
connection = sqlite3.connect('user.db')
cursor = connection.cursor()

#cursor.execute('ALTER TABLE files ADD status varchar(10) default enable')
cursor.execute('UPDATE files SET status = "enable"')
cursor.execute('DELETE FROM files WHERE name = "admin.txt"')

connection.commit()

# Закрытие соединения с базой данных
connection.close()
