# bsl_refactor_core.py
import re
from pathlib import Path

# Стандартные исключения (заглушки, пустые значения)
EXCLUDED_VALUES = {"", "не указан", "none", "null", "false", "true", "admin", "administrator"}

# Черный список папок (где не нужно искать/заменять секреты)
BLACKLIST_DIRS = {
    "Templates",     # Макеты
    "Forms",         # Формы
    "Ext",           # Внешние структуры
    "Tests",         # Тесты
    "Pictures"       # Картинки
}

# Белый список файлов модулей для конфигураций и обработок
WHITELIST_FILENAMES = {
    "ObjectModule.bsl",
    "ManagerModule.bsl",
    "RecordSetModule.bsl",
    "ValueModule.bsl",
    "Module.bsl"
}

def load_targets(file_path=None):
    """Загружает список целевых ключей/логинов из файла или возвращает дефолтный набор."""
    targets = set()
    if file_path and Path(file_path).exists():
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                clean = line.strip()
                if clean and not clean.startswith("#"):
                    targets.add(clean.lower())
    if not targets:
        # Дефолтные ключевые слова, если файл не задан
        targets = {"пароль", "password", "pwd", "логин", "login", "user", "token", "токен", "secret"}
    return targets

def get_safe_replacement(keyword):
    """Генерирует безопасный вызов БСП в зависимости от имени ключевого слова."""
    kw_lower = keyword.lower()
    if any(k in kw_lower for k in ["пароль", "password", "pwd", "secret"]):
        return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Пароль"
    elif any(k in kw_lower for k in ["логин", "user", "login"]):
        return "ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().Логин"
    else:
        return f"ОбщегоНазначенияКлиентСервер.ПолучитьПараметрыПодключения().{keyword.capitalize()}"

def should_skip_path(file_path, root_path):
    """Проверяет, входит ли файл в запрещенные каталоги."""
    try:
        rel_parts = Path(file_path).relative_to(root_path).parts
        for part in rel_parts:
            if part in BLACKLIST_DIRS:
                return True
    except ValueError:
        pass
    return False

def process_file_content(content, targets_regex):
    """Производит замену хардкода в тексте модуля и возвращает новый текст и счетчик замен."""
    replacements_count = 0
    
    def replace_match(match):
        nonlocal replacements_count
        keyword = match.group(1)
        secret_val = match.group(2).strip().lower()
        
        if secret_val and secret_val not in EXCLUDED_VALUES:
            replacements_count += 1
            safe_expr = get_safe_replacement(keyword)
            full_match = match.group(0)
            indent_match = re.match(r"^(\s*)", full_match)
            indent = indent_match.group(1) if indent_match else ""
            return f"{indent}{keyword} = {safe_expr};"
        return match.group(0)

    new_content = targets_regex.sub(replace_match, content)
    return new_content, replacements_count