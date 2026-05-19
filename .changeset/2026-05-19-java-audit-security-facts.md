---
"@critiq/adapter-java": minor
"@critiq/adapter-shared": minor
---

Add Java audit security adapter facts covering unsafe Jackson default typing, XXE-prone `DocumentBuilderFactory` / `SAXParserFactory` / `TransformerFactory` / `XMLInputFactory` usage, Hibernate `Session.createQuery` and `createNativeQuery` string concatenation, the shell form of `Runtime.getRuntime().exec(String)`, and `SecureRandom` constructors seeded with literal or short byte arrays.
