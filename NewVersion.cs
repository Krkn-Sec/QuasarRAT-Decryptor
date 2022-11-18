using dnlib.DotNet.Emit;
using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

//---------------------------
// For version 1.4 of Quasar
//---------------------------
namespace QuasarDecryptor
{
    public class NewVersion
    {
        enum valtype { Undefined, String, Integer, Sbyte, Boolean };
        static ModuleDefMD module = null;

        internal static void UpdatedVersionSearch(string filename)
        {
            string file = filename;
           

            //This dic will be filled with Quasar config values
            Dictionary<String, object> PROPERTIES = new Dictionary<String, object>();

            try
            {  //Load the module using Dnlib (for security reasons, NO LIVE DEBUGGING/NO ASSEMBLY LOADING)
                module = ModuleDefMD.Load(file);
                //Console.WriteLine(module);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error : " + e.Message);
                return;
            }

            //Get All the type from the binary
            IEnumerable<TypeDef> types = module.GetTypes();

            //Browse all types to find the Settings.cs one. Config values are initialized in the constructor
            foreach (var type in types)
            {
                if (PROPERTIES.Count() > 0) { break; }

                try
                {
                    //Console.WriteLine(type);
                    if (type.Fields.Count > 20 && type.Methods.Count == 4) // This is what I modified from the original code to get to the Settings.cs class.
                    {
                        //We should be in the "Settings" class
                        //Console.WriteLine(type);

                        //Get the constructor Body
                        MethodDef constructr = type.FindConstructors().First();
                        IList<Instruction> intrs = constructr.Body.Instructions;

                        if (intrs.Count == 0) { continue; }


                        //1) Fill the values

                        string strvalue = "";
                        string fieldname = "";
                        int intvalue = 0;
                        sbyte sb = 0;
                        bool boleanvalue = false;
                        valtype VAL = valtype.Undefined;

                        foreach (var op in intrs)
                        {
                            //Console.WriteLine(op);

                            if (op.OpCode.OperandType == OperandType.InlineString)
                            {
                                strvalue = (string)op.Operand;
                                VAL = valtype.String;
                                continue;
                            }

                            if ((op.OpCode.OperandType == OperandType.InlineI))
                            {
                                intvalue = (int)op.Operand;
                                VAL = valtype.Integer;
                                continue;
                            }

                            if (op.OpCode.OperandType == OperandType.ShortInlineI)
                            {
                                sb = (sbyte)op.Operand;
                                VAL = valtype.Sbyte;
                                continue;
                            }


                            switch (op.OpCode.ToString())
                            {
                                case "ldc.i4.0":
                                    VAL = valtype.Boolean;
                                    boleanvalue = false;
                                    break;

                                case "ldc.i4.1":
                                    VAL = valtype.Boolean;
                                    boleanvalue = true;
                                    break;

                                default:
                                    break;

                            }


                            if (op.OpCode.OperandType == OperandType.InlineField)
                            {
                                fieldname = op.Operand.ToString();
                                int index = fieldname.IndexOf("::");
                                fieldname = fieldname.Substring(index + 2, fieldname.Length - index - 2);

                                switch (VAL)
                                {


                                    case valtype.String:
                                        PROPERTIES.Add(fieldname, strvalue);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;

                                    case valtype.Integer:
                                        PROPERTIES.Add(fieldname, intvalue);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;

                                    case valtype.Sbyte:
                                        PROPERTIES.Add(fieldname, sb);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;

                                    case valtype.Boolean:
                                        PROPERTIES.Add(fieldname, boleanvalue);
                                        //Console.WriteLine(fieldname + " defined");
                                        break;


                                }

                                VAL = valtype.Undefined;

                            }


                        }


                        //2) Find the ENC KEY
                        // The Encryption key is used in the Main method of the Main class
                        // This class only has 3 methods : Main, cctor, ctor. One constructor is empty, we alreay know the other one so the main method is the last one

                        MethodDef M = null;
                        String ENCRYPTIONKEY = "";
                        foreach (MethodDef MD in type.Methods)
                        {
                            if (MD.Body.Instructions.Count > 0 && MD != constructr)
                            {
                                M = MD;
                                break;
                            }
                        }
                        intrs = M.Body.Instructions;


                        int counter = 0;

                        foreach (var op in intrs)
                        {
                            if (ENCRYPTIONKEY != "") { break; }

                            if (op.OpCode.OperandType == OperandType.InlineField)
                            {
                                counter++;

                                switch (counter)
                                {
                                    case 1:
                                        break;

                                    case 2:
                                        fieldname = op.Operand.ToString();
                                        int index = fieldname.IndexOf("::");
                                        fieldname = fieldname.Substring(index + 2, fieldname.Length - index - 2);

                                        if (PROPERTIES[fieldname] is String)
                                        {
                                            ENCRYPTIONKEY = (string)PROPERTIES[fieldname];

                                        }

                                        break;
                                }

                            }
                        } //ENCRYPTION KEY FOUND


                        //3)DISPLAY DECRYPTED VALUES

                        //Initialize encryption
                        AESNewVersion.SetDefaultKey(ENCRYPTIONKEY);
                        string[] arr = { };
                        List<string> list = new List<string>(arr.ToList());

                        foreach (KeyValuePair<String, object> KP in PROPERTIES)
                        {
                            string value = "";
                            try
                            {
                                value = KP.Value.ToString();

                                if ((KP.Value is String) && (KP.Key != fieldname))
                                {
                                    string tmp = AESNewVersion.Decrypt((string)KP.Value); //AES.Decrypt returns "" if something was wrong (i.e string not encrypted.. Not all config is encrypted)
                                    if (!String.IsNullOrEmpty(tmp))
                                    {
                                        value = tmp;
                                        list.Add(value);
                                    }
                                }

                            }
                            catch (Exception)
                            {

                            }
                            //Console.WriteLine(KP.Key + " = " + value);
                        }
                        Console.WriteLine("[+] QuasarRAT Version: " + list[0]);
                        Console.WriteLine("[+] C2 Server(s): " + list[1]);
                        return;


                    }


                }
                catch (Exception)
                {


                }


            }





        }
    }
}
