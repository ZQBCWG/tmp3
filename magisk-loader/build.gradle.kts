/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2021 - 2022 LSPosed Contributors
 */
import org.apache.tools.ant.filters.FixCrLfFilter
import org.apache.commons.codec.binary.Hex
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.EdECPrivateKey
import java.security.interfaces.EdECPublicKey
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.util.TreeSet
import java.security.MessageDigest
import android.databinding.tool.ext.capitalizeUS
plugins {
    alias(libs.plugins.agp.app)
    alias(libs.plugins.lsplugin.resopt)
}

val moduleName = "LSPosed"
val moduleBaseId = "lsposed"
val authors = "LSPosed Developers"

val injectedPackageName: String by rootProject.extra
val injectedPackageUid: Int by rootProject.extra

val defaultManagerPackageName: String by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra

android {
    flavorDimensions += "api"

    buildFeatures {
        prefab = true
        buildConfig = true
    }

    defaultConfig {
        applicationId = "org.lsposed.lspd"
        multiDexEnabled = false

        buildConfigField(
            "String",
            "DEFAULT_MANAGER_PACKAGE_NAME",
            """"$defaultManagerPackageName""""
        )
        buildConfigField("String", "MANAGER_INJECTED_PKG_NAME", """"$injectedPackageName"""")
        buildConfigField("int", "MANAGER_INJECTED_UID", """$injectedPackageUid""")
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles("proguard-rules.pro")
        }
    }

    externalNativeBuild {
        cmake {
            path("src/main/jni/CMakeLists.txt")
        }
    }

    productFlavors {
        all {
            externalNativeBuild {
                cmake {
                    arguments += "-DMODULE_NAME=${name.lowercase()}_$moduleBaseId"
                    arguments += "-DAPI=${name.lowercase()}"
                }
            }
        }

        create("Zygisk") {
            dimension = "api"
            externalNativeBuild {
                cmake {
                    arguments += "-DAPI_VERSION=1"
                }
            }
        }
    }
    namespace = "org.lsposed.lspd"
}
abstract class Injected @Inject constructor(val magiskDir: String) {
    @get:Inject
    abstract val factory: ObjectFactory
}

dependencies {
    implementation(projects.core)
    implementation(projects.hiddenapi.bridge)
    implementation(projects.services.managerService)
    implementation(projects.services.daemonService)
    compileOnly(libs.androidx.annotation)
    compileOnly(projects.hiddenapi.stubs)
}

val zipAll = task("zipAll") {
    group = "LSPosed"
}

val generateWebRoot = tasks.register<Copy>("generateWebRoot") {
    group = "LSPosed"
    val webroottmp = File("$projectDir/build/intermediates/generateWebRoot")
    val webrootsrc = File(webroottmp, "src")

    onlyIf {
        val os = org.gradle.internal.os.OperatingSystem.current()
        if (os.isWindows) {
            exec {
                commandLine("cmd", "/c", "where", "pnpm")
                isIgnoreExitValue = true
            }.exitValue == 0
        } else {
            exec {
                commandLine("which", "pnpm")
                isIgnoreExitValue = true
            }.exitValue == 0
        }
    }

    doFirst {
        webroottmp.mkdirs()
        webrootsrc.mkdirs()
    }

    from("$projectDir/src/webroot")
    into(webrootsrc)

    doLast {
        exec {
            workingDir = webroottmp
            commandLine("pnpm", "add", "-D", "parcel-bundler", "kernelsu")
        }
        exec {
            workingDir = webroottmp
            commandLine("./node_modules/.bin/parcel", "build", "src/index.html")
        }
    }
}

fun afterEval() = android.applicationVariants.forEach { variant ->
    val variantCapped = variant.name.replaceFirstChar { it.uppercase() }
    val variantLowered = variant.name.lowercase()
    val buildTypeCapped = variant.buildType.name.replaceFirstChar { it.uppercase() }
    val buildTypeLowered = variant.buildType.name.lowercase()
    val flavorCapped = variant.flavorName!!.replaceFirstChar { it.uppercase() }
    val flavorLowered = variant.flavorName!!.lowercase()

    val magiskDir = layout.buildDirectory.dir("magisk/$variantLowered")

    val moduleId = "${flavorLowered}_$moduleBaseId"
    val zipFileName = "$moduleName-v$verName-$verCode-${flavorLowered}-$buildTypeLowered.zip"

    val prepareMagiskFilesTask = tasks.register<Sync>("prepareMagiskFiles${variantCapped}") {
    group = "LSPosed"
    dependsOn(
        "assemble$variantCapped",
        ":app:package$buildTypeCapped",
        ":daemon:package$buildTypeCapped",
        ":dex2oat:externalNativeBuild${buildTypeCapped}",
        generateWebRoot
    )
    into(magiskDir)
    from("${rootProject.projectDir}/README.md")
    from("$projectDir/magisk_module") {
        exclude("module.prop", "customize.sh", "daemon")
    }
    from("$projectDir/magisk_module") {
        include("module.prop")
        expand(
            "moduleId" to moduleId,
            "versionName" to "v$verName",
            "versionCode" to verCode,
            "authorList" to authors,
            "updateJson" to "https://raw.githubusercontent.com/JingMatrix/LSPosed/master/magisk-loader/update/${flavorLowered}.json",
            "requirement" to when (flavorLowered) {
                "zygisk" -> "Requires Magisk 26.0+ and Zygisk enabled"
                else -> "No further requirements"
            },
            "api" to flavorCapped,
        )
        filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
    }
    from("$projectDir/magisk_module") {
        include("customize.sh", "daemon")
        val tokens = mapOf(
            "FLAVOR" to flavorLowered,
            "DEBUG" to if (buildTypeLowered == "debug") "true" else "false"
        )
        filter<ReplaceTokens>("tokens" to tokens)
        filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
    }
    from(project(":app").tasks.getByName("package$buildTypeCapped").outputs) {
        include("*.apk")
        rename(".*\\.apk", "manager.apk")
    }
    from(project(":daemon").tasks.getByName("package$buildTypeCapped").outputs) {
        include("*.apk")
        rename(".*\\.apk", "daemon.apk")
    }
    into("lib") {
        val libDir = variantCapped + "/strip${variantCapped}DebugSymbols"
        from(layout.buildDirectory.dir("intermediates/stripped_native_libs/$libDir/out/lib")) {
            include("**/liblspd.so")
        }
    }
    into("bin") {
        from(project(":dex2oat").layout.buildDirectory.dir("intermediates/cmake/$buildTypeLowered/obj")) {
            include("**/dex2oat")
            include("**/liboat_hook.so")
        }
    }
    val dexOutPath = if (buildTypeLowered == "release")
        layout.buildDirectory.dir("intermediates/dex/$variantCapped/minify${variantCapped}WithR8")
    else
        layout.buildDirectory.dir("intermediates/dex/$variantCapped/mergeDex$variantCapped")
    into("framework") {
        from(dexOutPath)
        rename("classes.dex", "lspd.dex")
    }
    into("webroot") {
        if (flavorLowered.startsWith("zygisk")) {
            from("$projectDir/build/intermediates/generateWebRoot/dist") {
                include("**/*.js")
                include("**/*.html")
            }
        }
    }
    val root = magiskDir.get().asFile

    doLast {
        if (file("private_key").exists()) {
            println("=== Guards the peace of Machikado ===")
            val privateKey = file("private_key").readBytes()
            val publicKey = file("public_key").readBytes()
            val namedSpec = NamedParameterSpec("Ed25519")
            val privKeySpec = EdECPrivateKeySpec(namedSpec, privateKey)
            val kf = KeyFactory.getInstance("Ed25519")
            val privKey = kf.generatePrivate(privKeySpec)
            val sig = Signature.getInstance("Ed25519")

            fun File.sha(realFile: File? = null) {
                sig.update(this.name.toByteArray())
                sig.update(0) // null-terminated string
                val real = realFile ?: this
                val buffer = ByteBuffer.allocate(8)
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .putLong(real.length())
                    .array()
                sig.update(buffer)
                real.forEachBlock { bytes, size ->
                    sig.update(bytes, 0, size)
                }
            }

            fun getSign(name: String, abi32: String, abi64: String) {
                val set = TreeSet<Pair<File, File?>> { o1, o2 ->
                    o1.first.path.replace("\\", "/")
                        .compareTo(o2.first.path.replace("\\", "/"))
                }
                set.add(Pair(root.resolve("module.prop"), null))
                set.add(Pair(root.resolve("sepolicy.rule"), null))
                set.add(Pair(root.resolve("post-fs-data.sh"), null))
                set.add(Pair(root.resolve("service.sh"), null))
                set.add(Pair(root.resolve("mazoku"), null))
                set.add(Pair(root.resolve("lib/libzygisk.so"), root.resolve("lib/$abi32/libzygisk.so")))
                set.add(Pair(root.resolve("lib64/libzygisk.so"), root.resolve("lib/$abi64/libzygisk.so")))
                set.add(Pair(root.resolve("bin/zygisk-ptrace32"), root.resolve("lib/$abi32/libzygisk_ptrace.so")))
                set.add(Pair(root.resolve("bin/zygisk-ptrace64"), root.resolve("lib/$abi64/libzygisk_ptrace.so")))
                set.add(Pair(root.resolve("bin/zygiskd32"), root.resolve("bin/$abi32/zygiskd")))
                set.add(Pair(root.resolve("bin/zygiskd64"), root.resolve("bin/$abi64/zygiskd")))
                sig.initSign(privKey)
                set.forEach { it.first.sha(it.second) }
                val signFile = root.resolve(name)
                signFile.writeBytes(sig.sign())
                signFile.appendBytes(publicKey)
            }

            getSign("machikado.arm", "armeabi-v7a", "arm64-v8a")
            getSign("machikado.x86", "x86", "x86_64")
        } else {
            println("no private_key found, this build will not be signed")
            root.resolve("machikado.arm").createNewFile()
            root.resolve("machikado.x86").createNewFile()
        }
        fileTree(root).visit {
            if (isDirectory) return@visit
            val md = MessageDigest.getInstance("SHA-256")
            file.forEachBlock(4096) { bytes, size ->
                md.update(bytes, 0, size)
            }
            file("${file.path}.sha256").writeText(Hex.encodeHexString(md.digest()))
        	}
    	}
	}
    
    val zipTask = task<Zip>("zip${variantCapped}") {
        group = "LSPosed"
        dependsOn(prepareMagiskFilesTask)
        archiveFileName = zipFileName
        destinationDirectory = file("$projectDir/release")
        from(magiskDir)
    }

    zipAll.dependsOn(zipTask)

    val adb: String = androidComponents.sdkComponents.adb.get().asFile.absolutePath
    val pushTask = task<Exec>("push${variantCapped}") {
        group = "LSPosed"
        dependsOn(zipTask)
        workingDir("${projectDir}/release")
        commandLine(adb, "push", zipFileName, "/data/local/tmp/")
    }
    val flashMagiskTask = task<Exec>("flashMagisk${variantCapped}") {
        group = "LSPosed"
        dependsOn(pushTask)
        commandLine(
            adb, "shell", "su", "-c",
            "magisk --install-module /data/local/tmp/${zipFileName}"
        )
    }
    task<Exec>("flashMagiskAndReboot${variantCapped}") {
        group = "LSPosed"
        dependsOn(flashMagiskTask)
        commandLine(adb, "shell", "su", "-c", "/system/bin/svc", "power", "reboot")
    }
    val flashKsuTask = task<Exec>("flashKsu${variantCapped}") {
        group = "LSPosed"
        dependsOn(pushTask)
        commandLine(
            adb, "shell", "su", "-c",
            "ksud module install /data/local/tmp/${zipFileName}"
        )
    }
    task<Exec>("flashKsuAndReboot${variantCapped}") {
        group = "LSPosed"
        dependsOn(flashKsuTask)
        commandLine(adb, "shell", "su", "-c", "/system/bin/svc", "power", "reboot")
    }
    val flashAPatchTask = task<Exec>("flashAPatch${variantCapped}") {
        group = "LSPosed"
        dependsOn(pushTask)
        commandLine(
            adb, "shell", "su", "-c",
            "apd module install /data/local/tmp/${zipFileName}"
        )
    }
    task<Exec>("flashAPatchAndReboot${variantCapped}") {
        group = "LSPosed"
        dependsOn(flashAPatchTask)
        commandLine(adb, "shell", "su", "-c", "/system/bin/svc", "power", "reboot")
    }
}

afterEvaluate {
    afterEval()
}

val adb: String = androidComponents.sdkComponents.adb.get().asFile.absolutePath
val killLspd = task<Exec>("killLspd") {
    group = "LSPosed"
    commandLine(adb, "shell", "su", "-c", "killall", "lspd")
    isIgnoreExitValue = true
}
val pushDaemon = task<Exec>("pushDaemon") {
    group = "LSPosed"
    dependsOn(":daemon:assembleDebug")
    workingDir(project(":daemon").layout.buildDirectory.dir("outputs/apk/debug"))
    commandLine(adb, "push", "daemon-debug.apk", "/data/local/tmp/daemon.apk")
}
val pushDaemonNative = task<Exec>("pushDaemonNative") {
    group = "LSPosed"
    dependsOn(":daemon:assembleDebug")
    doFirst {
        val abi: String = ByteArrayOutputStream().use { outputStream ->
            exec {
                commandLine(adb, "shell", "getprop", "ro.product.cpu.abi")
                standardOutput = outputStream
            }
            outputStream.toString().trim()
        }
        workingDir(project(":daemon").layout.buildDirectory.dir("intermediates/stripped_native_libs/debug/stripDebugDebugSymbols/out/lib/$abi"))
    }
    commandLine(adb, "push", "libdaemon.so", "/data/local/tmp/libdaemon.so")
}
val reRunDaemon = task<Exec>("reRunDaemon") {
    group = "LSPosed"
    dependsOn(pushDaemon, pushDaemonNative, killLspd)
    // tricky to pass a minus number to avoid the injection warning
    commandLine(
        adb, "shell", "ASH_STANDALONE=1", "su", "-mm", "-pc",
        "/data/adb/magisk/busybox sh /data/adb/modules/*_lsposed/service.sh --system-server-max-retry=-1&"
    )
    isIgnoreExitValue = true
}
val tmpApk = "/data/local/tmp/manager.apk"
val pushApk = task<Exec>("pushApk") {
    group = "LSPosed"
    dependsOn(":app:assembleDebug")
    doFirst {
        exec {
            commandLine(adb, "shell", "su", "-c", "rm", "-f", tmpApk)
        }
    }
    workingDir(project(":app").layout.buildDirectory.dir("outputs/apk/debug"))
    commandLine(adb, "push", "app-debug.apk", tmpApk)
}
val openApp = task<Exec>("openApp") {
    group = "LSPosed"
    commandLine(
        adb, "shell",
        "am", "start", "-c", "org.lsposed.manager.LAUNCH_MANAGER",
        "com.android.shell/.BugreportWarningActivity"
    )
}
task("reRunApp") {
    group = "LSPosed"
    dependsOn(pushApk)
    finalizedBy(reRunDaemon)
}

evaluationDependsOn(":app")
evaluationDependsOn(":daemon")
