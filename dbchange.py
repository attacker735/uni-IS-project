import sqlite3

# Подключаемся к базе данных
connection = sqlite3.connect('user.db')
curs = connection.cursor()
curs.execute("UPDATE user SET password = '$2b$12$mAXSlj7Cnzlhh8Z58v/hmeeU90/hnAzmOay/W./HVJNXBx4MqqLEa' WHERE login = 1111")
users = curs.fetchall()


connection.commit()
connection.close()