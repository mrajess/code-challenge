using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Diagnostics;
using System.Text.Json;

namespace SecurityAssessor.Pages
{
    public class ProcessStringModel : PageModel
    {
        [BindProperty]
        public string InputString { get; set; }
        public List<Result> ResultList { get; set; }
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
                                Name = "MFA is not enabled",
                                Description = "MFA is not enabled.",
                                SuggestedRemediation = "Enable MFA."
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
                                    Name = "Insecure port detected",
                                    Description = "Insecure port detected. Port is: " + port,
                                    SuggestedRemediation = "Change the port to a secure port."
                                });
                            }

                            if (port == 22)
                            {
                                findings.Add(new Finding
                                {
                                    Name = "SSH port detected",
                                    Description = "SSH port detected.",
                                    SuggestedRemediation = "Create NSG rule."
                                });
                            }

                            if (port == 3389)
                            {
                                findings.Add(new Finding
                                {
                                    Name = "RDP port detected",
                                    Description = "RDP port detected.",
                                    SuggestedRemediation = "Create NSG rule."
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
                                Description = "Resiliency risk detected. Consider using GRS for redundancy.",
                                SuggestedRemediation = "Change replication to GRS."
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

                    if (resource.Encryption is not null && !resource.Encryption.Value)
                    {

                        findings.Add(new Finding
                        {
                            Name = "Encryption is not enabled",
                            Description = "Encryption is not enabled.",
                            SuggestedRemediation = "Enable encryption."
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
                            Description = "Password detected.",
                            SuggestedRemediation = "Use a strong password."
                        });
                    }

                    return findings;
                }
            }

        }
    }
}
