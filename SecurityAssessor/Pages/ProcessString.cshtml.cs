using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
using System.Text.Json;

namespace SecurityAssessor.Pages
{
    public class ProcessStringModel : PageModel
    {
        [BindProperty]
        public required string InputString { get; set; }
        public required List<Result> ResultList { get; set; }
        public void OnPost()
        {
            ResultList = Assessment.RunAssessment(InputString);
        }
        public class RootObject
        {
            public Resource[] Resources { get; set; } = Array.Empty<Resource>();
        }

        public class Resource
        {
            public string Type { get; set; } = string.Empty;
            public string Name { get; set; } = string.Empty;
            public int?[] Open_ports { get; set; } = Array.Empty<int?>();
            public string Password { get; set; } = string.Empty;
            public bool? Encryption { get; set; }
            public bool? Mfa_enabled { get; set; }
            public Azure_Specific Azure_specific { get; set; } = new Azure_Specific();
        }

        public class Azure_Specific
        {
            public string Resource_group { get; set; } = string.Empty;
            public string Location { get; set; } = string.Empty;
            public string Vm_size { get; set; } = string.Empty;
            public string Account_tier { get; set; } = string.Empty;
            public string Replication { get; set; } = string.Empty;
            public string Db_service { get; set; } = string.Empty;
        }

        public class Result
        {
            public string ResourceID { get; set; } = string.Empty;
            public Finding[] Findings { get; set; } = Array.Empty<Finding>();
        }

        public class Finding
        {
            public string Name { get; set; } = string.Empty;
            public string Description { get; set; } = string.Empty;
            public string SuggestedRemediation { get; set; } = string.Empty;
        }

        public class Assessment
        {
            private static readonly JsonSerializerOptions jsonSerializerOptions = new()
            {
                PropertyNameCaseInsensitive = true
            };

            public static List<Result> RunAssessment(string jsonString)
            {
                List<Result> results = new();

                var resources = DeserializeObject(jsonString);

                MFAAssessment assessment = new(new NetworkAssessment(new ReplicationAssessment(new EncryptionAssessment(new PasswordAssessment()))));

                if (resources != null)
                {
                    foreach (var resource in resources.Resources)
                    {
                        var resourceFindings = assessment.Assess(resource).ToArray();
                        if (resourceFindings.Length > 0)
                        {
                            results.Add(new Result
                            {
                                ResourceID = resource.Name,
                                Findings = resourceFindings
                            });
                        }
                    }
                }

                return results;

            }

            private static RootObject? DeserializeObject(string jsonString)
            {
                var rootObject = JsonSerializer.Deserialize<RootObject>(jsonString, jsonSerializerOptions);
                if (rootObject != null)
                {
                    return rootObject;
                }
                else
                {
                    Debug.WriteLine("Deserialization failed.");
                    return null;
                }
            }

            public interface IAssessment
            {
                List<Finding> Assess(Resource resource);
            }

            public class MFAAssessment : IAssessment
            {
                private readonly IAssessment _assessment;
                public MFAAssessment(IAssessment assessment = null)
                {
                    _assessment = assessment;
                }

                public List<Finding> Assess(Resource resource)
                {
                    List<Finding> findings = new();


                    if (_assessment != null)
                    {
                        List<Finding> assessmentFindings = _assessment.Assess(resource);
                        findings.AddRange(assessmentFindings);
                    }

                    if (resource.GetType().GetProperty("Mfa_enabled") != null)
                    {
                        if (resource.Mfa_enabled == false)
                        {
                            findings.Add(new Finding
                            {
                                Name = "MFA is not enabled.",
                                Description = "MFA is critical to securing our identities. Please setup Entra MFA as per our standards.",
                                SuggestedRemediation = "Please refer to the following for additional guidance on how to remediate: https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-azure-mfa"
                            });
                        }
                    }

                    return findings;
                }
            }

            public class NetworkAssessment : IAssessment
            {
                private readonly IAssessment _assessment;
                public NetworkAssessment(IAssessment assessment = null)
                {
                    _assessment = assessment;
                }

                public List<Finding> Assess(Resource resource)
                {
                    List<Finding> findings = new();

                    if (_assessment != null)
                    {
                        List<Finding> assessmentFindings = _assessment.Assess(resource);
                        findings.AddRange(assessmentFindings);
                    }

                    if (resource.Open_ports.Length > 0)
                    {
                        foreach (var port in resource.Open_ports)
                        {
                            if (port != 443 && port != 22 && port != 3389)
                            {
                                findings.Add(new Finding
                                {
                                    Name = "Insecure port detected.",
                                    Description = "Insecure port detected. Port is: " + port + ". All web traffic should be over 443 and using a secure protocol (HTTPS). Use an NSG or service specific equivalents in the case of PaaS. Additionally, consider only exposing services via Application Gateway with WAF enabled.",
                                    SuggestedRemediation = "Please refer to the following for additional guidance on how to create an NSG and rule: https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group?tabs=network-security-group-portal and here for guidance on how to setup Application Gateway: https://learn.microsoft.com/en-us/azure/application-gateway/create-multiple-sites-portal."
                                });
                            }

                            if (port == 22)
                            {
                                findings.Add(new Finding
                                {
                                    Name = "SSH port (22) detected.",
                                    Description = "SSH port detected. Remote administration ports should not be exposed to the internet. Azure Bastion should be leveraged to securely administer your services.",
                                    SuggestedRemediation = "Please refer to the following for additional guidance on how to create an NSG and rule: https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group?tabs=network-security-group-portal and here for gudiance on how to setup Azure Bastion: https://learn.microsoft.com/en-us/azure/bastion/quickstart-host-portal."
                                });
                            }
                        
                            if (port == 3389)
                            {
                                findings.Add(new Finding
                                {
                                    Name = "RDP port (3389) detected.",
                                    Description = "RDP port detected. Remote administration ports should not be exposed to the internet. Azure Bastion should be leveraged to securely administer your services.",
                                    SuggestedRemediation = "Please refer to the following for additional guidance on how to create an NSG and rule: https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group?tabs=network-security-group-portal and here for gudiance on how to setup Azure Bastion: https://learn.microsoft.com/en-us/azure/bastion/quickstart-host-portal."
                                });
                            }
                        }
                    }


                    return findings;
                }
            }

            public class ReplicationAssessment : IAssessment
            {
                private readonly IAssessment _assessment;
                public ReplicationAssessment(IAssessment assessment = null)
                {
                    _assessment = assessment;
                }

                public List<Finding> Assess(Resource resource)
                {
                    List<Finding> findings = new();

                    if (_assessment != null)
                    {
                        List<Finding> assessmentFindings = _assessment.Assess(resource);
                        findings.AddRange(assessmentFindings);
                    }

                    if (!String.IsNullOrEmpty(resource.Azure_specific.Replication))
                    {
                        if (resource.Azure_specific.Replication.Equals("LRS"))
                        {
                            findings.Add(new Finding
                            {
                                Name = "Resiliency risk detected",
                                Description = "Presently data is not protected against a regional outage. This is merely a warning. Please consider implementing Geo-Redundant replication on your storage account.",
                                SuggestedRemediation = "Please refer to the following for additional guidance on how to remediate:  https://learn.microsoft.com/en-us/azure/storage/common/redundancy-migration?tabs=portal#changing-redundancy-configuration"
                            });
                        }
                    }


                    return findings;
                }
            }

            public class EncryptionAssessment : IAssessment
            {
                private readonly IAssessment _assessment;
                public EncryptionAssessment(IAssessment assessment = null)
                {
                    _assessment = assessment;
                }

                public List<Finding> Assess(Resource resource)
                {
                    List<Finding> findings = new();

                    if (_assessment != null)
                    {
                        List<Finding> assessmentFindings = _assessment.Assess(resource);
                        findings.AddRange(assessmentFindings);
                    }

                    if (resource.Encryption is not null && !resource.Encryption.Value && resource.Type == "database")
                    {

                        findings.Add(new Finding
                        {
                            Name = "Encryption is not enabled on database.",
                            Description = "Transparent Data Encryption is on by default on all Azure SQL servers. However, please implement customer managed keys as per our encryption standard.",
                            SuggestedRemediation = "Please refer to the following for additional guidance on how to remediate: https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-create-server?view=azuresql&tabs=azure-portal"
                        });
                    }
                    if (resource.Encryption is not null && !resource.Encryption.Value && resource.Type == "virtual_machine")
                    {

                        findings.Add(new Finding
                        {
                            Name = "Encryption is not enabled on virtual machine.",
                            Description = "Encryption is not enabled.",
                            SuggestedRemediation = "Please refer to the following for additional guidance on how to remediate: https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-portal-quickstart#encrypt-the-virtual-machine."
                        });
                    }
                    if (resource.Encryption is not null && !resource.Encryption.Value && resource.Type == "storage_account")
                    {

                        findings.Add(new Finding
                        {
                            Name = "Encryption is not enabled on storage account.",
                            Description = "Encryption at rest is on by default on all Azure Services and cannot be disabled. However, please implement customer managed keys as per our encryption standard.",
                            SuggestedRemediation = "Please refer to the following for additional guidance on how to remediate: https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-configure-existing-account?tabs=azure-portal."
                        });
                    }


                    return findings;
                }
            }

            public class PasswordAssessment : IAssessment
            {
                private readonly IAssessment _assessment;
                public PasswordAssessment(IAssessment assessment = null)
                {
                    _assessment = assessment;
                }

                public List<Finding> Assess(Resource resource)
                {
                    List<Finding> findings = new();

                    if (_assessment != null)
                    {
                        List<Finding> assessmentFindings = _assessment.Assess(resource);
                        findings.AddRange(assessmentFindings);
                    }

                    if (resource.Password.Length > 0)
                    {
                        findings.Add(new Finding
                        {
                            Name = "Password detected",
                            Description = "A plain text password was detected in your code. Passwords should be vaulted.",
                            SuggestedRemediation = "Please refer to the following for additional guidance on how to remediate: https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/key-vault-parameter?tabs=azure-cli."
                        });
                    }

                    return findings;
                }
            }

        }
    }
}
