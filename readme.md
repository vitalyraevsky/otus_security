# Just for education

The project was created exclusively for OTUS training materials.

## Packages and structure

The project consists of three main sections:

- `biometrics` - Classes and extensions for working with Class 2 and 3 biometric (e.g. fingerprint, face, or iris).
- `crypto` - Example of working with encryption, signature and keys, including old devices
- `storage` - Simple classes for implement DataStore, EncryptedFile and EncryptedSharedPreferences

## License

Unlicense


## Задание 1. Реализуйте безопасное хранение auth token:
Обязательно реализуйте шифрование полученного токена авторизации AES алгоритмом
Предусмотрите безопасное хранение ключа
Обеспечьте поддержку API < 23
Дополнительно
Используйте максимально безопастный режим шифрование (не ECB)
## Задание 2. Реализуйте вход используя биометрию:

Релизуйте авторизацию в приложение через BiometricPrompt
Обеспечьте поддержку STRONG и WEAK биометрию
Дополнительно
Добавьте возможность включать или отключать авторизацию через биометрию
Тестовый пользователь

Email: otus@test.com
Пароль: otus