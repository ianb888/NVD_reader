﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

using System.Xml.Serialization;

namespace SerializerLib
{
    // 
    // This source code was auto-generated by xsd, Version=4.6.81.0.
    // 

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    [XmlRoot(Namespace = "http://nvd.nist.gov/feeds/cve/1.2", IsNullable = false)]
    public partial class nvd
    {
        private entryType[] entryField;

        private string nvd_xml_versionField;

        private string pub_dateField;

        /// <remarks/>
        [XmlElement("entry")]
        public entryType[] entry
        {
            get
            {
                return this.entryField;
            }
            set
            {
                this.entryField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute(DataType = "NMTOKEN")]
        public string nvd_xml_version
        {
            get
            {
                return this.nvd_xml_versionField;
            }
            set
            {
                this.nvd_xml_versionField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string pub_date
        {
            get
            {
                return this.pub_dateField;
            }
            set
            {
                this.pub_dateField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    [XmlRoot("entry", Namespace = "http://nvd.nist.gov/feeds/cve/1.2", IsNullable = false)]
    public partial class entryType
    {
        private descriptType[] descField;

        private entryTypeImpacts impactsField;

        private solsType solsField;

        private lossTypeType loss_typesField;

        private vulnType vuln_typesField;

        private rangeType rangeField;

        private refType[] refsField;

        private vulnSoftTypeProd[] vuln_softField;

        private entryTypeType typeField;

        private string nameField;

        private string seqField;

        private string nvd_nameField;

        private string discoveredField;

        private string publishedField;

        private string modifiedField;

        private entryTypeSeverity severityField;

        private bool severityFieldSpecified;

        private trueOnlyAttribute rejectField;

        private bool rejectFieldSpecified;

        private string cVSS_versionField;

        private decimal cVSS_scoreField;

        private bool cVSS_scoreFieldSpecified;

        private decimal cVSS_base_scoreField;

        private bool cVSS_base_scoreFieldSpecified;

        private decimal cVSS_impact_subscoreField;

        private bool cVSS_impact_subscoreFieldSpecified;

        private decimal cVSS_exploit_subscoreField;

        private bool cVSS_exploit_subscoreFieldSpecified;

        private string cVSS_vectorField;

        /// <remarks/>
        [XmlArrayItem("descript", IsNullable = false)]
        public descriptType[] desc
        {
            get
            {
                return this.descField;
            }
            set
            {
                this.descField = value;
            }
        }

        /// <remarks/>
        public entryTypeImpacts impacts
        {
            get
            {
                return this.impactsField;
            }
            set
            {
                this.impactsField = value;
            }
        }

        /// <remarks/>
        public solsType sols
        {
            get
            {
                return this.solsField;
            }
            set
            {
                this.solsField = value;
            }
        }

        /// <remarks/>
        public lossTypeType loss_types
        {
            get
            {
                return this.loss_typesField;
            }
            set
            {
                this.loss_typesField = value;
            }
        }

        /// <remarks/>
        public vulnType vuln_types
        {
            get
            {
                return this.vuln_typesField;
            }
            set
            {
                this.vuln_typesField = value;
            }
        }

        /// <remarks/>
        public rangeType range
        {
            get
            {
                return this.rangeField;
            }
            set
            {
                this.rangeField = value;
            }
        }

        /// <remarks/>
        [XmlArrayItem("ref", IsNullable = false)]
        public refType[] refs
        {
            get
            {
                return this.refsField;
            }
            set
            {
                this.refsField = value;
            }
        }

        /// <remarks/>
        [XmlArrayItem("prod", IsNullable = false)]
        public vulnSoftTypeProd[] vuln_soft
        {
            get
            {
                return this.vuln_softField;
            }
            set
            {
                this.vuln_softField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public entryTypeType type
        {
            get
            {
                return this.typeField;
            }
            set
            {
                this.typeField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute(DataType = "ID")]
        public string name
        {
            get
            {
                return this.nameField;
            }
            set
            {
                this.nameField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute(DataType = "NMTOKEN")]
        public string seq
        {
            get
            {
                return this.seqField;
            }
            set
            {
                this.seqField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string nvd_name
        {
            get
            {
                return this.nvd_nameField;
            }
            set
            {
                this.nvd_nameField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string discovered
        {
            get
            {
                return this.discoveredField;
            }
            set
            {
                this.discoveredField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string published
        {
            get
            {
                return this.publishedField;
            }
            set
            {
                this.publishedField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string modified
        {
            get
            {
                return this.modifiedField;
            }
            set
            {
                this.modifiedField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public entryTypeSeverity severity
        {
            get
            {
                return this.severityField;
            }
            set
            {
                this.severityField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool severitySpecified
        {
            get
            {
                return this.severityFieldSpecified;
            }
            set
            {
                this.severityFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute reject
        {
            get
            {
                return this.rejectField;
            }
            set
            {
                this.rejectField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool rejectSpecified
        {
            get
            {
                return this.rejectFieldSpecified;
            }
            set
            {
                this.rejectFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string CVSS_version
        {
            get
            {
                return this.cVSS_versionField;
            }
            set
            {
                this.cVSS_versionField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public decimal CVSS_score
        {
            get
            {
                return this.cVSS_scoreField;
            }
            set
            {
                this.cVSS_scoreField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool CVSS_scoreSpecified
        {
            get
            {
                return this.cVSS_scoreFieldSpecified;
            }
            set
            {
                this.cVSS_scoreFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public decimal CVSS_base_score
        {
            get
            {
                return this.cVSS_base_scoreField;
            }
            set
            {
                this.cVSS_base_scoreField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool CVSS_base_scoreSpecified
        {
            get
            {
                return this.cVSS_base_scoreFieldSpecified;
            }
            set
            {
                this.cVSS_base_scoreFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public decimal CVSS_impact_subscore
        {
            get
            {
                return this.cVSS_impact_subscoreField;
            }
            set
            {
                this.cVSS_impact_subscoreField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool CVSS_impact_subscoreSpecified
        {
            get
            {
                return this.cVSS_impact_subscoreFieldSpecified;
            }
            set
            {
                this.cVSS_impact_subscoreFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public decimal CVSS_exploit_subscore
        {
            get
            {
                return this.cVSS_exploit_subscoreField;
            }
            set
            {
                this.cVSS_exploit_subscoreField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool CVSS_exploit_subscoreSpecified
        {
            get
            {
                return this.cVSS_exploit_subscoreFieldSpecified;
            }
            set
            {
                this.cVSS_exploit_subscoreFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string CVSS_vector
        {
            get
            {
                return this.cVSS_vectorField;
            }
            set
            {
                this.cVSS_vectorField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class descriptType
    {
        private descriptSourceType sourceField;

        private string valueField;

        /// <remarks/>
        [XmlAttribute()]
        public descriptSourceType source
        {
            get
            {
                return this.sourceField;
            }
            set
            {
                this.sourceField = value;
            }
        }

        /// <remarks/>
        [XmlText()]
        public string Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public enum descriptSourceType
    {
        /// <remarks/>
        cve,

        /// <remarks/>
        nvd,
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class refType
    {
        private string sourceField;

        private string urlField;

        private trueOnlyAttribute sigField;

        private bool sigFieldSpecified;

        private trueOnlyAttribute advField;

        private bool advFieldSpecified;

        private trueOnlyAttribute patchField;

        private bool patchFieldSpecified;

        private string valueField;

        /// <remarks/>
        [XmlAttribute()]
        public string source
        {
            get
            {
                return this.sourceField;
            }
            set
            {
                this.sourceField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute(DataType = "anyURI")]
        public string url
        {
            get
            {
                return this.urlField;
            }
            set
            {
                this.urlField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute sig
        {
            get
            {
                return this.sigField;
            }
            set
            {
                this.sigField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool sigSpecified
        {
            get
            {
                return this.sigFieldSpecified;
            }
            set
            {
                this.sigFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute adv
        {
            get
            {
                return this.advField;
            }
            set
            {
                this.advField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool advSpecified
        {
            get
            {
                return this.advFieldSpecified;
            }
            set
            {
                this.advFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute patch
        {
            get
            {
                return this.patchField;
            }
            set
            {
                this.patchField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool patchSpecified
        {
            get
            {
                return this.patchFieldSpecified;
            }
            set
            {
                this.patchFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlText()]
        public string Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public enum trueOnlyAttribute
    {
        /// <remarks/>
        [XmlEnum("1")]
        Item1,
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class rangeType
    {
        private object localField;

        private object local_networkField;

        private object networkField;

        private object user_initField;

        /// <remarks/>
        public object local
        {
            get
            {
                return this.localField;
            }
            set
            {
                this.localField = value;
            }
        }

        /// <remarks/>
        public object local_network
        {
            get
            {
                return this.local_networkField;
            }
            set
            {
                this.local_networkField = value;
            }
        }

        /// <remarks/>
        public object network
        {
            get
            {
                return this.networkField;
            }
            set
            {
                this.networkField = value;
            }
        }

        /// <remarks/>
        public object user_init
        {
            get
            {
                return this.user_initField;
            }
            set
            {
                this.user_initField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class vulnType
    {
        private object accessField;

        private vulnTypeInput inputField;

        private object designField;

        private object exceptionField;

        private object envField;

        private object configField;

        private object raceField;

        private object otherField;

        /// <remarks/>
        public object access
        {
            get
            {
                return this.accessField;
            }
            set
            {
                this.accessField = value;
            }
        }

        /// <remarks/>
        public vulnTypeInput input
        {
            get
            {
                return this.inputField;
            }
            set
            {
                this.inputField = value;
            }
        }

        /// <remarks/>
        public object design
        {
            get
            {
                return this.designField;
            }
            set
            {
                this.designField = value;
            }
        }

        /// <remarks/>
        public object exception
        {
            get
            {
                return this.exceptionField;
            }
            set
            {
                this.exceptionField = value;
            }
        }

        /// <remarks/>
        public object env
        {
            get
            {
                return this.envField;
            }
            set
            {
                this.envField = value;
            }
        }

        /// <remarks/>
        public object config
        {
            get
            {
                return this.configField;
            }
            set
            {
                this.configField = value;
            }
        }

        /// <remarks/>
        public object race
        {
            get
            {
                return this.raceField;
            }
            set
            {
                this.raceField = value;
            }
        }

        /// <remarks/>
        public object other
        {
            get
            {
                return this.otherField;
            }
            set
            {
                this.otherField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class vulnTypeInput
    {
        private trueOnlyAttribute boundField;

        private bool boundFieldSpecified;

        private trueOnlyAttribute bufferField;

        private bool bufferFieldSpecified;

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute bound
        {
            get
            {
                return this.boundField;
            }
            set
            {
                this.boundField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool boundSpecified
        {
            get
            {
                return this.boundFieldSpecified;
            }
            set
            {
                this.boundFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute buffer
        {
            get
            {
                return this.bufferField;
            }
            set
            {
                this.bufferField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool bufferSpecified
        {
            get
            {
                return this.bufferFieldSpecified;
            }
            set
            {
                this.bufferFieldSpecified = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class lossTypeType
    {
        private object availField;

        private object confField;

        private object intField;

        private lossTypeTypeSec_prot sec_protField;

        /// <remarks/>
        public object avail
        {
            get
            {
                return this.availField;
            }
            set
            {
                this.availField = value;
            }
        }

        /// <remarks/>
        public object conf
        {
            get
            {
                return this.confField;
            }
            set
            {
                this.confField = value;
            }
        }

        /// <remarks/>
        public object @int
        {
            get
            {
                return this.intField;
            }
            set
            {
                this.intField = value;
            }
        }

        /// <remarks/>
        public lossTypeTypeSec_prot sec_prot
        {
            get
            {
                return this.sec_protField;
            }
            set
            {
                this.sec_protField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class lossTypeTypeSec_prot
    {
        private trueOnlyAttribute adminField;

        private bool adminFieldSpecified;

        private trueOnlyAttribute userField;

        private bool userFieldSpecified;

        private trueOnlyAttribute otherField;

        private bool otherFieldSpecified;

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute admin
        {
            get
            {
                return this.adminField;
            }
            set
            {
                this.adminField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool adminSpecified
        {
            get
            {
                return this.adminFieldSpecified;
            }
            set
            {
                this.adminFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute user
        {
            get
            {
                return this.userField;
            }
            set
            {
                this.userField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool userSpecified
        {
            get
            {
                return this.userFieldSpecified;
            }
            set
            {
                this.userFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute other
        {
            get
            {
                return this.otherField;
            }
            set
            {
                this.otherField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool otherSpecified
        {
            get
            {
                return this.otherFieldSpecified;
            }
            set
            {
                this.otherFieldSpecified = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class solsType
    {
        private solsTypeSol solField;

        /// <remarks/>
        public solsTypeSol sol
        {
            get
            {
                return this.solField;
            }
            set
            {
                this.solField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class solsTypeSol
    {
        private solsSourceType sourceField;

        private string[] textField;

        /// <remarks/>
        [XmlAttribute()]
        public solsSourceType source
        {
            get
            {
                return this.sourceField;
            }
            set
            {
                this.sourceField = value;
            }
        }

        /// <remarks/>
        [XmlText()]
        public string[] Text
        {
            get
            {
                return this.textField;
            }
            set
            {
                this.textField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public enum solsSourceType
    {
        /// <remarks/>
        nvd,
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class impactType
    {
        private impactSourceType sourceField;

        private string valueField;

        /// <remarks/>
        [XmlAttribute()]
        public impactSourceType source
        {
            get
            {
                return this.sourceField;
            }
            set
            {
                this.sourceField = value;
            }
        }

        /// <remarks/>
        [XmlText()]
        public string Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [XmlType(Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public enum impactSourceType
    {
        /// <remarks/>
        nvd,
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class entryTypeImpacts
    {
        private impactType impactField;

        /// <remarks/>
        public impactType impact
        {
            get
            {
                return this.impactField;
            }
            set
            {
                this.impactField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class vulnSoftTypeProd
    {
        private vulnSoftTypeProdVers[] versField;

        private string nameField;

        private string vendorField;

        /// <remarks/>
        [XmlElement("vers")]
        public vulnSoftTypeProdVers[] vers
        {
            get
            {
                return this.versField;
            }
            set
            {
                this.versField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string name
        {
            get
            {
                return this.nameField;
            }
            set
            {
                this.nameField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string vendor
        {
            get
            {
                return this.vendorField;
            }
            set
            {
                this.vendorField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public partial class vulnSoftTypeProdVers
    {
        private string numField;

        private trueOnlyAttribute prevField;

        private bool prevFieldSpecified;

        private string editionField;

        /// <remarks/>
        [XmlAttribute()]
        public string num
        {
            get
            {
                return this.numField;
            }
            set
            {
                this.numField = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public trueOnlyAttribute prev
        {
            get
            {
                return this.prevField;
            }
            set
            {
                this.prevField = value;
            }
        }

        /// <remarks/>
        [XmlIgnore()]
        public bool prevSpecified
        {
            get
            {
                return this.prevFieldSpecified;
            }
            set
            {
                this.prevFieldSpecified = value;
            }
        }

        /// <remarks/>
        [XmlAttribute()]
        public string edition
        {
            get
            {
                return this.editionField;
            }
            set
            {
                this.editionField = value;
            }
        }
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public enum entryTypeType
    {
        /// <remarks/>
        CAN,

        /// <remarks/>
        CVE,
    }

    /// <remarks/>
    [System.CodeDom.Compiler.GeneratedCodeAttribute("xsd", "4.6.81.0")]
    [System.SerializableAttribute()]
    [XmlType(AnonymousType = true, Namespace = "http://nvd.nist.gov/feeds/cve/1.2")]
    public enum entryTypeSeverity
    {
        /// <remarks/>
        High,

        /// <remarks/>
        Medium,

        /// <remarks/>
        Low,
    }
}