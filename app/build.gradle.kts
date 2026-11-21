plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// A chave de assinatura NÃO fica no repositório.
// No GitHub Actions ela vem dos Secrets (ver .github/workflows/build.yml).
// No computador, defina as mesmas variáveis de ambiente para gerar o release.
val keystorePath: String? = System.getenv("KEYSTORE_PATH")

android {
    namespace = "com.exemplo.bloqueador"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.exemplo.bloqueador"
        minSdk = 24
        targetSdk = 34
        versionCode = 4
        versionName = "4.0"
    }

    signingConfigs {
        if (keystorePath != null) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD")
                storeType = "pkcs12"
            }
        }
    }

    buildTypes {
        release {
            // R8: remove código e recursos não usados (APK bem menor)
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            isDebuggable = false
            if (keystorePath != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures { buildConfig = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
