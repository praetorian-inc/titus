plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.praetorian.titus"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // JSON parsing
    implementation("com.google.code.gson:gson:2.10.1")

    // Burp Suite Montoya API (compile only - provided by Burp at runtime)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2023.12.1")

    // Testing
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    testImplementation("org.mockito:mockito-core:5.8.0")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2023.12.1")
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName.set("titus-burp")
    archiveClassifier.set("all")

    manifest {
        attributes(
            "Extension-Name" to "Titus Secret Scanner",
            "Extension-Version" to version,
            "Extension-Author" to "Praetorian"
        )
    }

    // Relocate Gson to avoid conflicts with other extensions
    relocate("com.google.gson", "com.praetorian.titus.shadow.gson")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
