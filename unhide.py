import os
import ctypes

def unhide_file(file_path):
    # Снимаем атрибут "Скрытый", оставляя остальные
    FILE_ATTRIBUTE_HIDDEN = 0x02
    attributes = ctypes.windll.kernel32.GetFileAttributesW(file_path)
    
    if attributes == -1:
        print(f"Не удалось получить атрибуты файла {file_path}. Ошибка: {ctypes.GetLastError()}")
        return
    
    # Убираем флаг HIDDEN
    new_attributes = attributes & ~FILE_ATTRIBUTE_HIDDEN
    result = ctypes.windll.kernel32.SetFileAttributesW(file_path, new_attributes)
    
    if result:
        print(f"Файл {file_path} теперь видим.")
    else:
        print(f"Не удалось сделать файл видимым {file_path}. Ошибка: {ctypes.GetLastError()}")

# Папка, где лежит скрипт
files_dir = os.path.dirname(os.path.abspath(__file__))

# Проходим по всем файлам в директории
for file_name in os.listdir(files_dir):
    if file_name.endswith('.txt'):  # Обрабатываем только .txt файлы
        full_path = os.path.join(files_dir, file_name)
        unhide_file(full_path)
