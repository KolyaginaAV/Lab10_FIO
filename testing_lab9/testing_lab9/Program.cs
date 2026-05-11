using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
using Serilog;

namespace testing_lab9
{
    class Program
    {
        // Предустановленный список логинов, с которыми нельзя совпадать
        private static readonly HashSet<string> ForbiddenLogins = new HashSet<string>
        {
            "admin", "root", "user", "test", "guest", "administrator"
        };

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            // Настройка Serilog
            string template = "{Timestamp:HH:mm:ss} | [{Level:u3}] | {Message:lj}{NewLine}{Exception}";
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console(outputTemplate: template)
                .WriteTo.File("logs/log.txt", outputTemplate: template, rollingInterval: RollingInterval.Day)
                .CreateLogger();

            Log.Information("Приложение запущено");

            Console.WriteLine("=== Регистрация пользователя ===\n");

            while (true)
            {
                Console.Write("Логин: ");
                string login = Console.ReadLine();

                Console.Write("Пароль: ");
                string password = ReadPassword();

                Console.Write("Подтверждение пароля: ");
                string confirmPassword = ReadPassword();

                var (result, message) = ValidateRegistration(login, password, confirmPassword);

                Console.WriteLine($"\nРезультат: {result}");
                if (!string.IsNullOrEmpty(message))
                    Console.WriteLine($"Ошибка: {message}");

                Console.WriteLine(new string('-', 50) + "\n");
            }
        }

        // Метод для скрытого ввода пароля (звёздочки)
        private static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password.Substring(0, password.Length - 1);
                    Console.Write("\b \b");
                }
            } while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password;
        }

        // Маскирование пароля (хэширование)
        private static string MaskPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                return "***";

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashBytes).Substring(0, 8) + "...";
            }
        }

        // ОСНОВНОЙ МЕТОД ВАЛИДАЦИИ
        public static (string Result, string Message) ValidateRegistration(string login, string password, string confirmPassword)
        {
            string maskedPassword = MaskPassword(password);
            string maskedConfirm = MaskPassword(confirmPassword);

            // 1. Проверка на null или пустые строки
            if (string.IsNullOrEmpty(login))
            {
                Log.Error("Логин не может быть пустым | Логин: null | Пароль: {MaskedPwd} | Подтверждение: {MaskedConf}", maskedPassword, maskedConfirm);
                return ("False", "Логин не может быть пустым");
            }

            if (string.IsNullOrEmpty(password))
            {
                Log.Error("Пароль не может быть пустым | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConf}", login, maskedPassword, maskedConfirm);
                return ("False", "Пароль не может быть пустым");
            }

            // 2. Проверка логина (телефон, email или строка)
            string loginError = ValidateLogin(login);
            if (loginError != null)
            {
                Log.Error("Ошибка логина: {Error} | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConf}",
                    loginError, login, maskedPassword, maskedConfirm);
                return ("False", loginError);
            }

            // 3. Проверка пароля
            string passwordError = ValidatePassword(password);
            if (passwordError != null)
            {
                Log.Error("Ошибка пароля: {Error} | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConf}",
                    passwordError, login, maskedPassword, maskedConfirm);
                return ("False", passwordError);
            }

            // 4. Проверка совпадения паролей
            if (password != confirmPassword)
            {
                Log.Error("Пароли не совпадают | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConf}",
                    login, maskedPassword, maskedConfirm);
                return ("False", "Пароль и подтверждение пароля не совпадают");
            }

            // 5. Успешная регистрация
            Log.Information("УСПЕШНАЯ РЕГИСТРАЦИЯ | Логин: {Login} | Пароль: {MaskedPwd} | Подтверждение: {MaskedConf}",
                login, maskedPassword, maskedConfirm);

            return ("True", "");
        }

        private static string ValidateLogin(string login)
        {
            // Проверка на запрещённые логины
            if (ForbiddenLogins.Contains(login.ToLower()))
                return "Данный логин запрещён (административный или зарезервированный)";

            // Вариант 1: Телефон (+x-xxx-xxx-xxxx)
            Regex phoneRegex = new Regex(@"^\+\d-\d{3}-\d{3}-\d{4}$");
            if (phoneRegex.IsMatch(login))
                return null; // валидный телефон

            // Вариант 2: Email (xxx@xxx.xxx)
            Regex emailRegex = new Regex(@"^[^@]+@[^@]+\.[^@]+$");
            if (emailRegex.IsMatch(login))
                return null; // валидный email

            // Вариант 3: Обычная строка (минимум 5 символов, латиница, цифры, _)
            Regex stringRegex = new Regex(@"^[a-zA-Z0-9_]{5,}$");
            if (stringRegex.IsMatch(login))
                return null; // валидная строка

            return "Логин должен быть: телефоном (+X-XXX-XXX-XXXX), email (xxx@xxx.xxx) или строкой (мин. 5 символов, латиница, цифры, _)";
        }

        private static string ValidatePassword(string password)
        {
            // Минимум 7 символов
            if (password.Length < 7)
                return "Пароль должен содержать минимум 7 символов";

            // Только кириллица, цифры и спецсимволы (разрешённые)
            Regex allowedChars = new Regex(@"^[а-яА-ЯёЁ0-9!@#$%^&*()_+=\[\]{};:'\\|,.<>/?-]+$");
            if (!allowedChars.IsMatch(password))
                return "Пароль может содержать только кириллицу, цифры и спецсимволы";

            // Хотя бы одна заглавная буква
            if (!Regex.IsMatch(password, @"[А-ЯЁ]"))
                return "Пароль должен содержать хотя бы одну заглавную букву";

            // Хотя бы одна строчная буква
            if (!Regex.IsMatch(password, @"[а-яё]"))
                return "Пароль должен содержать хотя бы одну строчную букву";

            // Хотя бы одна цифра
            if (!Regex.IsMatch(password, @"[0-9]"))
                return "Пароль должен содержать хотя бы одну цифру";

            // Хотя бы один спецсимвол
            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+=\[\]{};:'\\|,.<>/?-]"))
                return "Пароль должен содержать хотя бы один спецсимвол";

            return null; // пароль валидный
        }
    }
}
