-- PasswordManager.hs
-- Administrador de contraseñas con cifrado y persistencia

import System.IO (hSetEcho, stdin, stdout, hFlush, hReady, hSetBuffering, BufferMode(NoBuffering, LineBuffering))
import System.Directory
import Data.List
import Data.Char
import System.Console.ANSI (clearScreen)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Base64 as B64
import Control.Exception (catch, IOException)
import Control.Monad (when, forM_)
import Control.Concurrent (threadDelay)


-- ==================== TIPOS DE DATOS ====================

data User = User {
    userId :: Int,
    username :: String,
    pinHash :: String
} deriving (Show, Read)

data PasswordEntry = PasswordEntry {
    ownerId :: Int,
    title :: String,
    loginUser :: String,
    password :: String
} deriving (Show, Read)

-- ==================== FUNCIONES DE CIFRADO ====================

-- Convierte un dígito a representación binaria de 4 bits
digitToBinary :: Char -> String
digitToBinary c 
    | c == '0' = "0000"
    | c == '1' = "0001"
    | c == '2' = "0010"
    | c == '3' = "0011"
    | c == '4' = "0100"
    | c == '5' = "0101"
    | c == '6' = "0110"
    | c == '7' = "0111"
    | c == '8' = "1000"
    | c == '9' = "1001"
    | otherwise = "0000"  -- Por seguridad

-- Cifrado de PIN de 4 dígitos
encodePin :: String -> String
encodePin pin = 
    if all isDigit pin && length pin == 4
        then concatMap digitToBinary (reverse pin)
        else "" 

-- Verificación de PIN
verifyPin :: String -> String -> Bool
verifyPin inputPin storedEncoded = 
    if all isDigit inputPin && length inputPin == 4
        then encodePin inputPin == storedEncoded
        else False -- PIN inválido formato, retorna falso en lugar de error

-- Cifrado para contraseñas
encrypt :: String -> String -> String
encrypt key text = 
    let keyStream = cycle key
    in zipWith encryptChar text keyStream
  where
    encryptChar c k = 
        let cVal = ord c
            kVal = ord k
            -- Usamos un rango de 128 para cubrir todos los caracteres ASCII básicos
            encVal = ((cVal + kVal) `mod` 128)
        in chr encVal

-- Descifrado para contraseñas 
decrypt :: String -> String -> String
decrypt key text = 
    let keyStream = cycle key
    in zipWith decryptChar text keyStream
  where
    decryptChar c k = 
        let cVal = ord c
            kVal = ord k
            -- Crucial: añadir 128 antes del módulo para manejar negativos correctamente
            decVal = ((cVal - kVal + 128) `mod` 128)
        in chr decVal

-- Convertir a Base64 para almacenamiento seguro
encryptAndEncode :: String -> String
encryptAndEncode text = 
    let secretKey = "H4sk3llSecretK3y"  -- Clave fija del sistema
        encrypted = encrypt secretKey text
    in BS.unpack $ B64.encode $ BS.pack encrypted

-- Decodificar de Base64 y descifrar
decodeAndDecrypt :: String -> String
decodeAndDecrypt encoded = 
    let secretKey = "H4sk3llSecretK3y"  -- Misma clave fija
        -- Decodificar Base64 primero
        decodedBytes = BS.unpack $ either (const BS.empty) id $ B64.decode $ BS.pack encoded
        -- Luego aplicar descifrado
        decrypted = decrypt secretKey decodedBytes
    in decrypted

-- ==================== GESTIÓN DE USUARIOS ====================

-- Cargar usuarios del archivo
-- Cargar usuarios del archivo
loadUsers :: IO [User]
loadUsers = do
    exists <- doesFileExist "users.txt"
    if not exists
        then return []
        else do
            -- Leer todo el contenido
            content <- readFile "users.txt"
            -- Forzar la evaluación COMPLETA del contenido
            let contentLength = length content
            contentLength `seq` return ()
            
            let nonEmptyLines = filter (not . null) (lines content)
            let users = if null nonEmptyLines 
                        then []
                        else if "id,username,hash_del_pin" `isPrefixOf` head nonEmptyLines
                             then map parseUser (tail nonEmptyLines)
                             else map parseUser nonEmptyLines
            
            -- Forzar evaluación completa de la lista de usuarios
            let userCount = length users
            userCount `seq` return users
  where
    parseUser line = 
        let [idStr, name, hash] = splitOn ',' line
        in User (read idStr) name hash

-- Guardar usuarios en el archivo
saveUsers :: [User] -> IO ()
saveUsers users = do
    let header = "id,username,hash_del_pin"
    let userLines = map (\u -> show (userId u) ++ "," ++ username u ++ "," ++ pinHash u) users
    let content = unlines (header : userLines)
    
    -- Escritura directa, sin archivos temporales
    writeFile "users.txt" content

-- Generar nuevo ID de usuario
generateUserId :: [User] -> Int
generateUserId users = 
    if null users 
        then 1 
        else maximum (map userId users) + 1

-- Registrar un nuevo usuario
registerUser :: String -> String -> [User] -> IO User
registerUser name pin users = do
    let newId = generateUserId users
    let encodedPin = encodePin pin
    let newUser = User newId name encodedPin
    saveUsers (newUser : users)
    return newUser

-- Buscar usuario por nombre
findUserByName :: String -> [User] -> Maybe User
findUserByName name = find (\u -> username u == name)

-- ==================== GESTIÓN DE CONTRASEÑAS ====================

-- Cargar contraseñas del archivo
loadAllPasswords :: IO [PasswordEntry]
loadAllPasswords = do
    exists <- doesFileExist "passwords.txt"
    if exists
        then do
            content <- readFile "passwords.txt"
            let nonEmptyLines = filter (not . null) (lines content)
            if null nonEmptyLines 
                then return [] -- Archivo vacío
                else do
                    let passLines = if "user_id,title,username,password" `isPrefixOf` head nonEmptyLines
                                    then tail nonEmptyLines
                                    else nonEmptyLines
                    return $ map parseRawPasswordEntry passLines
        else return []
  where
    parseRawPasswordEntry line = 
        let [ownerIdStr, title, user, pass] = splitOn ',' line
        in PasswordEntry (read ownerIdStr) title user pass

-- Cargar contraseñas de un usuario específico
loadUserPasswords :: Int -> IO [PasswordEntry]
loadUserPasswords uid = do
    allPasswords <- loadAllPasswords
    let userPasswords = filter (\e -> ownerId e == uid) allPasswords
    -- Impresión de debug (puedes quitar esto después)
    putStrLn $ "DEBUG: Contraseña antes de descifrar: " ++ (if null userPasswords then "" else password $ head userPasswords)
    
    let decrypted = map decryptPassword userPasswords
    -- Impresión de debug (puedes quitar esto después)
    putStrLn $ "DEBUG: Contraseña después de descifrar: " ++ (if null decrypted then "" else password $ head decrypted)
    
    return decrypted
  where
    decryptPassword entry = 
        PasswordEntry 
            (ownerId entry)
            (title entry)
            (loginUser entry)
            (decodeAndDecrypt (password entry))

-- Guardar todas las contraseñas
saveAllPasswords :: [PasswordEntry] -> IO ()
saveAllPasswords entries = do
    let header = "user_id,title,username,password"
    let entryLines = map formatEntry entries
    let content = unlines (header : entryLines)
    
    -- Escritura directa, sin archivos temporales
    writeFile "passwords.txt" content
  where
    formatEntry entry = intercalate "," [
        show (ownerId entry),
        title entry,
        loginUser entry,
        password entry
      ]

-- Función segura para guardar contraseñas evitando bloqueos de archivos
savePasswordsSafely :: Int -> [PasswordEntry] -> PasswordEntry -> IO ()
savePasswordsSafely userId userPasswords newEncryptedEntry = do
    if null userPasswords
        then do
            -- Si no hay contraseñas, solo guardar las otras
            let header = "user_id,title,username,password"
            let entryLines = map formatEntry userPasswords
            let content = unlines (header : entryLines)
            writeFile "passwords.txt" content
        else do
            -- Primero, crear un archivo temporal
            let tempFile = "passwords_temp.txt"
            
            -- Intentar cargar las contraseñas existentes (con manejo de errores)
            existingPasswords <- catch loadAllPasswords (\(_ :: IOException) -> return [])
            
            -- Filtrar las contraseñas que no son del usuario actual
            let otherPasswords = filter (\e -> ownerId e /= userId) existingPasswords
            
            -- Preparar todas las contraseñas del usuario actual para guardar (cifradas)
            let encryptedUserPasswords = map encryptForStorage userPasswords
            
            -- Juntar todas las contraseñas
            let allEntries = encryptedUserPasswords ++ otherPasswords
            
            -- Generar el contenido del archivo
            let header = "user_id,title,username,password"
            let entryLines = map formatEntry allEntries
            let content = unlines (header : entryLines)

            -- Escribir primero al archivo temporal
            writeFile tempFile content

            -- Esperar un poco para asegurar que se complete la escritura
            threadDelay 500000  -- 0.5 segundos

            -- Ahora intentar reemplazar el archivo original
            catch (do
                    removeFile "passwords.txt"
                    renameFile tempFile "passwords.txt"
                ) 
                (\(_ :: IOException) -> 
                    -- Si falla el renombrado, intenta copiar el contenido directamente
                    writeFile "passwords.txt" content
                )
          where
            formatEntry entry = intercalate "," [
                show (ownerId entry),
                title entry,
                loginUser entry,
                password entry
              ]

-- Agregar una nueva contraseña
addPassword :: User -> String -> [PasswordEntry] -> IO [PasswordEntry]
addPassword user pin passwords = do
    putStrLn "\n=== Agregar Nueva Contraseña ==="
    putStrLn "Ingrese título/sitio:"
    entryTitle <- getLine
    putStrLn "Ingrese nombre de usuario:"
    entryUser <- getLine
    putStrLn "Ingrese contraseña:"
    entryPass <- getPassword
    
    let encryptedPass = encryptAndEncode entryPass 
    let newEntry = PasswordEntry (userId user) entryTitle entryUser encryptedPass
    
    -- Crear versiones desencriptadas y encriptadas para diferentes propósitos
    let newEntryDecrypted = PasswordEntry (userId user) entryTitle entryUser entryPass
    
    -- Preparar contraseñas para guardar en archivo (usando archivo temporal)
    savePasswordsSafely (userId user) (passwords ++ [newEntryDecrypted]) newEntry
    
    -- Devolver las contraseñas actualizadas para la sesión actual
    return (passwords ++ [newEntryDecrypted])

-- Modificar una contraseña 
modifyPassword :: User -> String -> [PasswordEntry] -> IO [PasswordEntry]
modifyPassword user pin passwords = do
    putStrLn "\n=== Modificar Contraseña ==="
    displayPasswords passwords
    putStrLn "Ingrese el ID de la contraseña a modificar:"
    idStr <- getLine
    let id = read idStr :: Int
    
    if id > 0 && id <= length passwords
        then do
            let entry = passwords !! (id - 1)
            putStrLn $ "Título del sitio: " ++ title entry
            
            putStrLn "Ingrese nuevo usuario (enter para mantener el actual):"
            newUser <- getLine
            let user' = if null newUser then loginUser entry else newUser
            
            putStrLn "Ingrese nueva contraseña (enter para mantener la actual):"
            newPass <- getPassword
            let pass' = if null newPass then password entry else newPass
            
            -- Crear la entrada actualizada (versión descifrada para el usuario actual)
            let updatedEntry = PasswordEntry (ownerId entry) (title entry) user' pass'
            let updatedPasswords = take (id - 1) passwords ++ [updatedEntry] ++ drop id passwords
            
            -- Crear la entrada cifrada para almacenamiento
            let encryptedEntry = PasswordEntry (ownerId entry) (title entry) user' (encryptAndEncode pass')
            
            -- Usar savePasswordsSafely en lugar de saveAllPasswords
            savePasswordsSafely (userId user) updatedPasswords encryptedEntry
            
            putStrLn "Contraseña modificada correctamente."
            return updatedPasswords
        else do
            putStrLn "ID inválido."
            return passwords

-- Eliminar una contraseña
deletePassword :: User -> String -> [PasswordEntry] -> IO [PasswordEntry]
deletePassword user pin passwords = do
    putStrLn "\n=== Eliminar Contraseña ==="
    displayPasswords passwords
    putStrLn "Ingrese el ID de la contraseña a eliminar:"
    idStr <- getLine
    let id = read idStr :: Int
    
    if id > 0 && id <= length passwords
        then do
            -- Solo necesitamos las contraseñas actualizadas (sin la eliminada)
            let updatedPasswords = take (id - 1) passwords ++ drop id passwords
            
            -- Usar savePasswordsSafely con cualquier entrada (no importa cuál ya que solo importa updatedPasswords)
            -- El tercer parámetro no se usa realmente en esta operación de eliminación
            savePasswordsSafely (userId user) updatedPasswords (head updatedPasswords)
            
            putStrLn "Contraseña eliminada correctamente."
            return updatedPasswords
        else do
            putStrLn "ID inválido."
            return passwords

-- Preparar una entrada para almacenamiento (cifrar contraseña)
encryptForStorage :: PasswordEntry -> PasswordEntry
encryptForStorage entry = 
    PasswordEntry 
        (ownerId entry)
        (title entry)
        (loginUser entry)
        (encryptAndEncode (password entry))

-- ==================== FUNCIONES DE INTERFAZ ====================

-- Entrada oculta para contraseñas
getPassword :: IO String
getPassword = do
    -- Configurar el buffer explícitamente
    hSetBuffering stdout NoBuffering
    hSetBuffering stdin NoBuffering
    
    hSetEcho stdin False  -- Desactivar eco
    result <- getPasswordChar []
    hSetEcho stdin True  -- Reactivar eco
    putChar '\n'  -- Nueva línea al final
    
    -- Restaurar buffers
    hSetBuffering stdout LineBuffering
    hSetBuffering stdin LineBuffering
    
    return result
  where
    getPasswordChar acc = do
        char <- getChar
        case char of
            '\n' -> return acc
            '\DEL' -> do
                if null acc
                    then getPasswordChar acc
                    else do
                        putChar '\b'
                        putChar ' '
                        putChar '\b'
                        hFlush stdout
                        getPasswordChar (init acc)
            _ -> do
                putChar '*'
                hFlush stdout
                getPasswordChar (acc ++ [char])

-- Función para dividir una cadena
splitOn :: Char -> String -> [String]
splitOn delimiter = foldr f [[]]
  where
    f c acc@(x:xs) | c == delimiter = []:acc
                   | otherwise = (c:x):xs

-- Máscara para nombres de usuario
maskUsername :: String -> String
maskUsername user 
    | length user <= 4 = user
    | otherwise = take 2 user ++ replicate (length user - 4) '*' ++ drop (length user - 2) user

-- Limpiar pantalla con manejo de errores
safeClearScreen :: IO ()
safeClearScreen = catch clearScreen (\(_ :: IOException) -> return ())

-- Mostrar contraseñas en tabla
displayPasswords :: [PasswordEntry] -> IO ()
displayPasswords entries = do
    putStrLn "╔═════╦════════════════════╦════════════════════╦════════════════╗"
    putStrLn "║ ID  ║        Título      ║      Usuario       ║   Contraseña   ║"
    putStrLn "╠═════╬════════════════════╬════════════════════╬════════════════╣"
    forM_ (zip [1..] entries) $ \(id, entry) ->
        putStrLn $ "║ " ++ padRight 3 (show id) ++ " ║ " 
                 ++ padRight 18 (title entry) ++ " ║ " 
                 ++ padRight 18 (maskUsername $ loginUser entry) ++ " ║ " 
                 ++ padRight 14 "********" ++ " ║"
    putStrLn "╚═════╩════════════════════╩════════════════════╩════════════════╝"
  where
    padRight n str = take n (str ++ repeat ' ')

-- Copiar usuario al portapapeles
copyUsernameToClipboard :: User -> String -> [PasswordEntry] -> IO ()
copyUsernameToClipboard user pin passwords = do
    putStrLn "\n=== Ver Usuario Completo ==="
    displayPasswords passwords
    putStrLn "Ingrese el ID de la entrada:"
    idStr <- getLine
    let id = read idStr :: Int
    
    if id > 0 && id <= length passwords
        then do
            let entry = passwords !! (id - 1)
            putStrLn $ "\nTítulo del sitio: " ++ title entry
            putStrLn $ "Usuario completo: " ++ loginUser entry
            putStrLn "Presione Enter para continuar..."
            _ <- getLine
            return ()
        else do
            putStrLn "ID inválido."
            putStrLn "Presione Enter para continuar..."
            _ <- getLine
            return ()

-- Ver contraseña completa
viewPassword :: User -> String -> [PasswordEntry] -> IO ()
viewPassword user pin passwords = do
    putStrLn "\n=== Ver Contraseña Completa ==="
    displayPasswords passwords
    putStrLn "Ingrese el ID de la contraseña a ver:"
    idStr <- getLine
    let id = read idStr :: Int
    
    if id > 0 && id <= length passwords
        then do
            let entry = passwords !! (id - 1)
            let decryptedPass = decodeAndDecrypt (password entry)
            putStrLn $ "\nTítulo del sitio: " ++ title entry
            putStrLn $ "Contraseña (original): " ++ password entry
            putStrLn "\nPresione Enter para continuar..."
            _ <- getLine
            return ()
        else do
            putStrLn "ID inválido."
            putStrLn "Presione Enter para continuar..."
            _ <- getLine
            return ()

-- Cambiar PIN de usuario
changeUserPin :: User -> String -> [PasswordEntry] -> IO ()
changeUserPin user currentPin passwords = do
    putStrLn "\n=== Cambiar PIN de Acceso ==="
    putStrLn "Ingrese su PIN actual para confirmar:"
    confirmPin <- getPassword
    
    if verifyPin confirmPin (pinHash user)
        then do
            putStrLn "Ingrese su nuevo PIN (4 dígitos numéricos):"
            newPin <- getPassword
            
            if all isDigit newPin && length newPin == 4
                then do
                    -- 1. Crear el usuario actualizado
                    let updatedUser = User (userId user) (username user) (encodePin newPin)
                    
                    -- 2. Actualizar solo el archivo de usuarios (no toca passwords.txt)
                    usersData <- loadUsers
                    let otherUsers = filter (\u -> userId u /= userId user) usersData
                    saveUsers (updatedUser : otherUsers)
                    
                    putStrLn "PIN actualizado correctamente."
                    putStrLn "Presione Enter para continuar..."
                    _ <- getLine
                    passwordMenu updatedUser newPin passwords
                else do
                    putStrLn "El PIN debe ser numérico y tener exactamente 4 dígitos."
                    passwordMenu user currentPin passwords
        else do
            putStrLn "PIN actual incorrecto."
            passwordMenu user currentPin passwords

-- ==================== MENÚS DE USUARIO ====================

-- Menú de gestión de contraseñas
passwordMenu :: User -> String -> [PasswordEntry] -> IO ()
passwordMenu user pin passwords = do
    safeClearScreen
    putStrLn $ "=== Usuario: " ++ username user ++ " (ID: " ++ show (userId user) ++ ") ==="
    displayPasswords passwords
    putStrLn "\nOpciones:"
    putStrLn "1. Agregar contraseña"
    putStrLn "2. Ver contraseña completa"
    putStrLn "3. Modificar contraseña o usuario"
    putStrLn "4. Eliminar contraseña"
    putStrLn "5. Ver usuario completo"
    putStrLn "6. Cambiar PIN de acceso"
    putStrLn "0. Cerrar sesión"
    putStrLn "----------------------------------------"
    putStr "Seleccione una opción: "
    choice <- getLine
    
    case choice of
        "1" -> do
            updatedPasswords <- addPassword user pin passwords
            passwordMenu user pin updatedPasswords
        "2" -> do
            if null passwords
                then do
                    putStrLn "\nNo hay contraseñas guardadas."
                    putStrLn "Presione Enter para continuar..."
                    _ <- getLine
                    passwordMenu user pin passwords
                else do
                    viewPassword user pin passwords
                    passwordMenu user pin passwords
        "3" -> do
            updatedPasswords <- modifyPassword user pin passwords
            passwordMenu user pin updatedPasswords
        "4" -> do
            updatedPasswords <- deletePassword user pin passwords
            passwordMenu user pin updatedPasswords
        "5" -> do
            if null passwords
                then do
                    putStrLn "\nNo hay contraseñas guardadas."
                    putStrLn "Presione Enter para continuar..."
                    _ <- getLine
                    passwordMenu user pin passwords
                else do
                    copyUsernameToClipboard user pin passwords
                    putStrLn "¿Desea copiar el nombre de usuario al portapapeles? (s/n)"
                    choice <- getLine
                    when (choice == "s") $ do
                        putStrLn "Nombre de usuario copiado al portapapeles."
                        threadDelay 1000000  -- Esperar 1 segundo para simular la copia al portapapeles
            passwordMenu user pin passwords
        "6" -> changeUserPin user pin passwords
        "0" -> mainMenu
        _   -> do
            putStrLn "Opción inválida."
            putStrLn "Presione Enter para continuar..."
            _ <- getLine
            passwordMenu user pin passwords

-- Menú de registro
registerMenu :: IO ()
registerMenu = do
    safeClearScreen
    putStrLn "\n=== Registro de Nuevo Usuario ==="
    putStrLn "Ingrese nombre de usuario:"
    name <- getLine
    users <- loadUsers
    
    if any (\u -> username u == name) users
        then do
            putStrLn "Este nombre de usuario ya existe."
            putStrLn "Presione Enter para continuar..."
            _ <- getLine
            mainMenu
        else do
            putStrLn "Ingrese un PIN (exactamente 4 dígitos numéricos):"
            pin <- getPassword
            
            if all isDigit pin && length pin == 4
                then do
                    newUser <- registerUser name pin users
                    putStrLn "¡Usuario registrado con éxito!"
                    putStrLn "Presione Enter para continuar..."
                    _ <- getLine
                    mainMenu
                else do
                    putStrLn "El PIN debe ser numérico y tener exactamente 4 dígitos."
                    putStrLn "Presione Enter para continuar..."
                    _ <- getLine
                    registerMenu

-- Menú de inicio de sesión
loginMenu :: IO ()
loginMenu = do
    safeClearScreen
    putStrLn "\n=== Inicio de Sesión ==="
    putStrLn "Ingrese nombre de usuario:"
    name <- getLine
    users <- loadUsers
    
    case findUserByName name users of
        Nothing -> do
            putStrLn "Usuario no encontrado."
            putStrLn "Presione Enter para continuar..."
            _ <- getLine
            mainMenu
        Just user -> do
            putStr "Ingrese su PIN (4 dígitos): "
            hFlush stdout
            pin <- getPassword
            
            if verifyPin pin (pinHash user)
                then do
                    passwords <- loadUserPasswords (userId user)  -- Quitar el segundo parámetro pin
                    passwordMenu user pin passwords
                else do
                    putStrLn "PIN incorrecto."
                    putStrLn "Presione Enter para continuar..."
                    _ <- getLine
                    mainMenu

-- Menú principal
mainMenu :: IO ()
mainMenu = do
    safeClearScreen
    putStrLn "========================================"
    putStrLn "=== ADMINISTRADOR SEGURO DE CONTRASEÑAS ==="
    putStrLn "========================================"
    putStrLn "1. Iniciar sesión"
    putStrLn "2. Crear nuevo usuario"
    putStrLn "0. Salir"
    putStrLn "----------------------------------------"
    putStr "Seleccione una opción: "
    choice <- getLine
    case choice of
        "1" -> loginMenu
        "2" -> registerMenu
        "0" -> putStrLn "¡Hasta luego!"
        _   -> do
            putStrLn "Opción inválida."
            putStrLn "Presione Enter para continuar..."
            _ <- getLine
            mainMenu

-- ==================== FUNCIÓN PRINCIPAL ====================

testEncryption :: IO ()
testEncryption = do
    let original = "Orlkasesina06."
    putStrLn $ "Original: " ++ original
    
    let encrypted = encryptAndEncode original
    putStrLn $ "Encriptado+Base64: " ++ encrypted
    
    let decrypted = decodeAndDecrypt encrypted
    putStrLn $ "Desencriptado: " ++ decrypted
    
    putStrLn $ "¿Coinciden? " ++ show (original == decrypted)

main :: IO ()
main = do
    testEncryption

    -- Crear archivos si no existen
    usersExist <- doesFileExist "users.txt"
    when (not usersExist) $ do
        writeFile "users.txt" "id,username,hash_del_pin\n"
    
    passwordsExist <- doesFileExist "passwords.txt"
    when (not passwordsExist) $ do
        writeFile "passwords.txt" "user_id,title,username,password\n"
    
    mainMenu