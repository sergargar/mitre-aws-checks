# Script for AWS Compliance Verifications

Simple overview of use/purpose.

## Description

An in-depth paragraph about your project and overview of use.

## Getting Started

### Dependencies

* It is necessary to have Python3 installed with the packages boto3 and termcolor
* The packages can be installed with the following command:
```
pip3 install boto3 termcolor
```

### User Creation

* How/where to download your program
* Any modifications needed to be made to files/folders

### Customize verification functions

* The following parameters can be customized in some functions:
* 
| Function                 | Input Parameter                                                                                          | Description                                                                                                                                                                                           |
|-------------------------|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| inactive_users          | days_without_access                                                                                | Días sin acceder de un usuario para que se considere como inactivo.                                                                                                                                   |
| access_keys_rotation    | keys_older_than_days                                                                               | Días de antigüedad de las llaves de acceso para que se roten.                                                                                                                                         |
| s3_public_access        | account                                                                                            | Cuenta AWS donde se quiere verificar las políticas de acceso público de S3.                                                                                                                           |
| strong_password_policy  | password_length                                                                                    | Longitud mínima y máximo de días de expiración de las contraseñas, y el número de últimas contraseñas que no se pueden reutilizar, requerido en la política de contraseñas de la cuenta AWS.          |
| least_privilege_iam     | JobId                                                                                              | ID del job que el usuario ha generado previamente con la llamada de AWS generate_service_last_accessed_details(Arn=<entityArn>,Granularity='ACTION_LEVEL'), eligiendo la entidad que quiere analizar. |
| days_without_being_used | Días sin utilizar un servicio y/o acciones por una entidad para que se considere como inutilizado. |                                                                                                                                                                                                       |
| inspector_enabled       | days_since_last_assessment                                                                         | Días desde la última evaluación de Inspector para que se considere como no cumplido.                                                                                                                  |                                                                                                       |

### Executing program

* Once the user is created and the credentials were configured, the script can be executed with:
```
python3 main.py
```


## MITRE ATT&CK Mapping

* The functions of the script can mitigate the following adversary techniques that are describe in the [IaaS Matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/):



## Version History

* 1.0
    * Initial Release
